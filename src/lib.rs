#![doc = include_str!("../README.md")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Instant, Duration};
use std::array::from_fn;
use std::str::from_utf8;
use std::sync::Arc;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use futures_rustls::TlsConnector;
use rustls::client::ClientConfig;
use async_net::TcpStream;
use litemap::LiteMap;
use dns_packet::{Reader, Writer, Header, Question, MessageType, QueryType, DnsError};

mod hash;

type TlsStream = futures_rustls::client::TlsStream<TcpStream>;

type Hash = u64;
type CacheKey = (Hash, ResourceType);

type DataProc<T> = fn(&mut Reader, usize) -> Option<T>;
type Getter<T> = fn(&mut CacheValue) -> &mut Option<Records<T>>;

const LEN_PREFIX: usize = 2;
const MAX_LEN: usize = u16::MAX as usize;
const QCLASS_INTERNET: u16 = 1;
const DOT_PORT: u16 = 853;

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
enum ResourceType {
    A = 1,
    NS = 2,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    AAAA = 28,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// A TCP connection to the server could not be opened (Port 853)
    InitialConnect,
    /// The TLS handshake did not succeed
    Handshake,
    /// The request could not be encoded due to length of domain name
    PacketLength,
    /// Something is unexpected in the received response
    Decoding,
    /// The request could not be sent through the TLS connection
    Request,
    /// The response could not be received through the TLS connection
    Response,
}

struct Records<T> {
    expiration: Instant,
    items: Vec<T>,
}

/// One Mail Exchange Server reported by the DNS server
#[derive(Clone, Debug, PartialEq)]
pub struct MailServer {
    /// Lower values are preferred
    pub preference: u16,
    /// host will be a domain name
    pub host: String,
}

#[derive(Default)]
struct CacheValue {
    ipv4: Option<Records<Ipv4Addr>>,
    ipv6: Option<Records<Ipv6Addr>>,
    cname: Option<Records<String>>,
    mail: Option<Records<MailServer>>,
    text: Option<Records<String>>,
    name: Option<Records<String>>,
}

/// # Name Resolver
///
/// See crate root for examples.
pub struct Resolver {
    cache: LiteMap<CacheKey, CacheValue>,
    connector: TlsConnector,
    server_ip: IpAddr,
    stream: Option<TlsStream>,
    buffer: Vec<u8>,
    msg_id: u16,
}

impl Resolver {
    /// Internal structure initialization
    pub fn new(server_ip: IpAddr, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            cache: LiteMap::new(),
            msg_id: 0,
            connector: tls_config.into(),
            server_ip,
            stream: None,
            buffer: vec![0; LEN_PREFIX],
        }
    }

    async fn lookup<'a, T: 'a>(
        &'a mut self,
        name: &str,
        resource_type: ResourceType,
        data_proc: DataProc<T>,
        getter: Getter<T>,
    ) -> Result<&'a [T], Error> {
        if !dns_packet::valid_name(name) {
            return Err(Error::PacketLength);
        }

        let key = (hash::hash_str(name), resource_type);
        let mut update = true;

        if let Some(value_ref) = self.cache.get_mut(&key) {
            if let Some(field) = getter(value_ref) {
                if Instant::now() < field.expiration {
                    // rustc doesn't want me to return a borrow of self here :(
                    update = false;
                }
            }
        }

        if update {
            self.encode_question(name, resource_type)?;
            self.request(name, resource_type).await?;
            self.process_records(key, data_proc, getter)?;
        }

        let field = getter(&mut self.cache[&key]).as_ref();

        Ok(&field.expect("cant be none").items)
    }

    /// Performs an `A` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_ipv4<'a>(&'a mut self, name: &str) -> Result<&'a [Ipv4Addr], Error> {
        self.lookup(name, ResourceType::A, proc_ipv4, get_ipv4).await
    }

    /// Performs an `AAAA` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_ipv6<'a>(&'a mut self, name: &str) -> Result<&'a [Ipv6Addr], Error> {
        self.lookup(name, ResourceType::AAAA, proc_ipv6, get_ipv6).await
    }

    /// Performs a `CNAME` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_cname<'a>(&'a mut self, name: &str) -> Result<&'a [String], Error> {
        self.lookup(name, ResourceType::CNAME, proc_name, get_cname).await
    }

    /// Performs an `MX` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_mail<'a>(&'a mut self, name: &str) -> Result<&'a [MailServer], Error> {
        self.lookup(name, ResourceType::MX, proc_mail, get_mail).await
    }

    /// Performs a `NS` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_ns<'a>(&'a mut self, name: &str) -> Result<&'a [String], Error> {
        self.lookup(name, ResourceType::NS, proc_name, get_name).await
    }

    /// Performs a `TXT` resource lookup for a specific domain name
    ///
    /// If valid data is found in the internal cache, it will be
    /// returned directly without sending any request to the DNS server.
    ///
    /// If a request is necessary and the connection is closed, a new
    /// connection will be established. You may close it using `Resolver::disconnect`.
    pub async fn lookup_txt<'a>(&'a mut self, name: &str) -> Result<&'a [String], Error> {
        self.lookup(name, ResourceType::TXT, proc_text, get_text).await
    }

    fn encode_len(&mut self, len: usize) -> Result<(), Error> {
        if len > MAX_LEN {
            return Err(Error::PacketLength);
        }

        let len_field = (len as u16).to_be_bytes();
        self.buffer[..LEN_PREFIX].copy_from_slice(&len_field);

        Ok(())
    }

    fn decode_len(&self) -> usize {
        let len_field = from_fn(|i| self.buffer[i]);
        u16::from_be_bytes(len_field) as usize
    }

    async fn connect(&mut self) -> Result<(), Error> {
        let Ok(tcp_stream) = TcpStream::connect((self.server_ip, DOT_PORT)).await else {
            return Err(Error::InitialConnect);
        };

        let Ok(stream) = self.connector.connect(self.server_ip.into(), tcp_stream).await else {
            return Err(Error::Handshake);
        };

        self.stream = Some(stream);
        Ok(())
    }

    /// Closes the internal TLS connection to the DNS server.
    ///
    /// If the connection was already closed, this does nothing.
    pub fn disconnect(&mut self) {
        self.stream.take();
    }

    async fn maybe_retry(
        &mut self,
        old_connection: bool,
        name: &str,
        resource_type: ResourceType,
        error: Error,
    ) -> Result<(), Error> {
        self.disconnect();

        match old_connection {
            true => Box::pin(self.request(name, resource_type)).await,
            false => Err(error),
        }
    }

    fn encode_question(&mut self, name: &str, resource_type: ResourceType) -> Result<(), Error> {
        let id = self.msg_id;
        self.msg_id += 1;

        let header = Header {
            id,
            mtype: MessageType::Query,
            qtype: QueryType::Standard,
            truncated: false,
            recursion_desired: true,
            question_count: 1,
            answer_count: 0,
            nameserver_count: 0,
            additional_count: 0,
        };

        let question = Question {
            name,
            qtype: resource_type as u16,
            qclass: QCLASS_INTERNET,
        };

        self.buffer.truncate(LEN_PREFIX);

        let mut writer = Writer {
            packet: &mut self.buffer,
        };

        writer.write_header(&header);
        writer.write_question(&question);
        self.encode_len(self.buffer.len() - LEN_PREFIX)
    }

    async fn request(&mut self, name: &str, resource_type: ResourceType) -> Result<(), Error> {
        let mut old_connection = true;

        if self.stream.is_none() {
            self.connect().await?;
            old_connection = false;
        }

        let stream = self.stream.as_mut().expect("see self.connect()");

        let Ok(_) = stream.write_all(&self.buffer).await else {
            return self.maybe_retry(old_connection, name, resource_type, Error::Request).await;
        };

        let mut received = 0;

        loop {
            self.buffer.resize(received + 2048, 0);
            let dst = &mut self.buffer[received..];
            let stream = self.stream.as_mut().expect("see self.connect()");

            let Ok(progress) = stream.read(dst).await else {
                return self.maybe_retry(old_connection, name, resource_type, Error::Response).await;
            };

            if progress == 0 {
                return self.maybe_retry(old_connection, name, resource_type, Error::Response).await;
            }

            received += progress;
            if received < LEN_PREFIX {
                continue;
            }

            let expected = LEN_PREFIX + self.decode_len();
            if received > LEN_PREFIX && expected <= received {
                self.buffer.truncate(expected);
                break;
            }
        }

        Ok(())
    }

    fn process_records<T>(
        &mut self,
        key: CacheKey,
        data_proc: DataProc<T>,
        getter: Getter<T>,
    ) -> Result<(), Error> {
        let response = &self.buffer[LEN_PREFIX..];
        let mut reader = Reader::new(response);

        let header = reader.read_header().ok_or(Error::Decoding)?;
        let mut answer_count = header.answer_count;

        let MessageType::Response(rdata) = header.mtype else {
            return Err(Error::Decoding)?;
        };

        if let Some(DnsError::NotFound) = rdata.error {
            answer_count = 0;
        } else if header.question_count != 1 || rdata.error.is_some() {
            return Err(Error::Decoding);
        }

        self.cache.try_insert(key, CacheValue::default());
        let handle = &mut self.cache[&key];
        let records = getter(handle);

        let question = reader.read_question().ok_or(Error::Decoding)?;
        let qtype = question.qtype;

        let mut items = Vec::new();
        let mut min_ttl = 24 * 3600;
        let mut unsolicited = 0;

        for _ in 0..answer_count {
            let answer = reader.read_resource().ok_or(Error::Decoding)?;
            let ttl = answer.time_to_live as u64;
            let len = answer.data_len as usize;

            // skip unrelated answers... why are they a thing
            if answer.qtype != qtype {
                let _ = reader.read(len).ok_or(Error::Decoding)?;
                unsolicited += 1;
                continue;
            }

            let result = data_proc(&mut reader, len);
            items.push(result.ok_or(Error::Decoding)?);
            min_ttl = min_ttl.min(ttl);
        }

        // if there were no actual answers
        if answer_count == unsolicited {
            min_ttl = 0;
        };

        let min_ttl = Duration::from_secs(min_ttl.into());
        let expiration = Instant::now() + min_ttl;

        let collection = Records {
            expiration,
            items,
        };

        *records = Some(collection);

        Ok(())
    }
}

fn get_ipv4(value: &mut CacheValue) -> &mut Option<Records<Ipv4Addr>> { &mut value.ipv4 }
fn get_ipv6(value: &mut CacheValue) -> &mut Option<Records<Ipv6Addr>> { &mut value.ipv6 }
fn get_cname(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.cname }
fn get_mail(value: &mut CacheValue) -> &mut Option<Records<MailServer>> { &mut value.mail }
fn get_text(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.text }
fn get_name(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.name }

fn proc_ipv4(reader: &mut Reader, len: usize) -> Option<Ipv4Addr> {
    (len == 4).then_some(())?;
    Some(reader.read_array()?.into())
}

fn proc_ipv6(reader: &mut Reader, len: usize) -> Option<Ipv6Addr> {
    (len == 16).then_some(())?;
    Some(reader.read_array()?.into())
}

fn proc_mail(reader: &mut Reader, len: usize) -> Option<MailServer> {
    let limit = reader.offset + len;

    let preference = reader.read_u16()?;
    let host = reader.read_name()?.to_string();

    if limit != reader.offset {
        return None;
    }

    Some(MailServer {
        preference,
        host,
    })
}

fn proc_text(reader: &mut Reader, len: usize) -> Option<String> {
    let mut slice = reader.read(len)?;
    let mut string = String::new();

    while let Some((len_byte, then)) = slice.split_first() {
        let len = *len_byte as usize;
        let (this, next) = then.split_at_checked(len)?;
        string += from_utf8(this).ok()?;
        slice = next;
    }

    Some(string)
}

fn proc_name(reader: &mut Reader, len: usize) -> Option<String> {
    let limit = reader.offset + len;
    let name = reader.read_name()?.into();
    (reader.offset == limit).then_some(name)
}
