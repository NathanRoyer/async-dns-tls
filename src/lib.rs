#![doc = include_str!("../README.md")]

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Instant, Duration};
use futures_rustls::TlsConnector;
use rustls::client::ClientConfig;
use async_net::TcpStream;
use std::array::from_fn;
use std::str::from_utf8;
use std::ops::AddAssign;
use litemap::LiteMap;
use std::iter::once;
use std::sync::Arc;

mod hash;

type TlsStream = futures_rustls::client::TlsStream<TcpStream>;

type Hash = u64;
type CacheKey = (Hash, ResourceType);

type DataProc<T> = fn(&[u8], usize, usize) -> Option<T>;
type Getter<T> = fn(&mut CacheValue) -> &mut Option<Records<T>>;

const LEN_PREFIX: usize = 2;
const MAX_LEN: usize = u16::MAX as usize;
const SAFE_LEN: usize = 16384;
const HEADER_LEN: usize = 0xC;
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
    req_len: usize,
    msg_id: u16,
}

impl Resolver {
    /// Internal structure initialization
    pub fn new(server_ip: IpAddr, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            cache: LiteMap::new(),
            msg_id: 0,
            req_len: 0,
            connector: tls_config.into(),
            server_ip,
            stream: None,
            buffer: vec![0; LEN_PREFIX + MAX_LEN],
        }
    }

    async fn lookup<'a, T: 'a>(
        &'a mut self,
        name: &str,
        resource_type: ResourceType,
        data_proc: DataProc<T>,
        getter: Getter<T>,
    ) -> Result<&'a [T], Error> {
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
        let msg_id = (self.msg_id + 1).to_be_bytes();
        self.msg_id += 1;

        // HEADER (12 bytes)

        self.buffer[0x2] = msg_id[0];
        self.buffer[0x3] = msg_id[1];
        self.buffer[0x4] = 1; // flags A: use recursion
        self.buffer[0x5] = 0; // flags B: none
        self.buffer[0x6] = 0; // question count
        self.buffer[0x7] = 1; // = 1
        self.buffer[0x8] = 0; // answer count
        self.buffer[0x9] = 0; // = 0
        self.buffer[0xa] = 1; // authority count
        self.buffer[0xb] = 0; // = 0
        self.buffer[0xc] = 1; // additional count
        self.buffer[0xd] = 0; // = 0

        let mut i = LEN_PREFIX + HEADER_LEN;

        // QUESTION

        for part in name.split('.').chain(once("")) {
            if part.len() > 63 || i + part.len() > SAFE_LEN {
                return Err(Error::PacketLength);
            }

            self.buffer[i] = part.len() as u8;
            let start = i + 1;
            i = start + part.len();
            let bytes = part.as_bytes();
            self.buffer[start..i].copy_from_slice(bytes);
        }

        let qtype = (resource_type as u16).to_be_bytes();

        self.buffer[i + 0] = qtype[0];
        self.buffer[i + 1] = qtype[1];
        self.buffer[i + 2] = 0; // qclass = INTERNET (high bits)
        self.buffer[i + 3] = 1; // qclass = INTERNET (low bits)
        i += 4;

        self.req_len = i;
        self.encode_len(i - LEN_PREFIX)
    }

    async fn request(&mut self, name: &str, resource_type: ResourceType) -> Result<(), Error> {
        let mut old_connection = true;

        if self.stream.is_none() {
            self.connect().await?;
            old_connection = false;
        }

        let packet = &self.buffer[..self.req_len];
        let stream = self.stream.as_mut().expect("see self.connect()");

        let Ok(_) = stream.write_all(packet).await else {
            return self.maybe_retry(old_connection, name, resource_type, Error::Request).await;
        };

        let mut received = 0;
        let mut expected;

        loop {
            let dst = &mut self.buffer[received..];
            let stream = self.stream.as_mut().expect("see self.connect()");
            let Ok(progress) = stream.read(dst).await else {
                return self.maybe_retry(old_connection, name, resource_type, Error::Response).await;
            };

            if progress == 0 {
                return self.maybe_retry(old_connection, name, resource_type, Error::Response).await;
            }

            received += progress;
            expected = LEN_PREFIX + self.decode_len();
            if received > LEN_PREFIX && expected <= received {
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
        let expected = LEN_PREFIX + self.decode_len();
        let response = &self.buffer[LEN_PREFIX..expected];

        if response.len() < HEADER_LEN {
            return Err(Error::Decoding);
        }

        let a = self.buffer[0x6];
        let b = self.buffer[0x7];
        let question_count = u16::from_be_bytes([a, b]);

        let a = self.buffer[0x8];
        let b = self.buffer[0x9];
        let mut answer_count = u16::from_be_bytes([a, b]);

        let rcode = self.buffer[0x5] & 0xf;

        if rcode == 3 {
            answer_count = 0;
        } else if question_count != 1 || rcode != 0 {
            println!("qcount = {:?}, rcode = {:?}", question_count, rcode);
            return Err(Error::Decoding);
        }

        self.cache.try_insert(key, CacheValue::default());
        let handle = &mut self.cache[&key];
        let records = getter(handle);

        // point to start of question
        let mut i = HEADER_LEN;

        // skip question (name, qtype, qclass)
        let _name: Sink = name_at(response, &mut i).ok_or(Error::Decoding)?;
        i += 4;

        let mut items = Vec::new();
        let mut min_ttl = 24 * 3600;

        if answer_count == 0 {
            min_ttl = 0;
        };

        for _ in 0..answer_count {
            let (ttl, data_len) = try_parse_answer(response, &mut i).ok_or(Error::Decoding)?;
            min_ttl = min_ttl.min(ttl as u64);

            let result = data_proc(response, i, data_len);
            items.push(result.ok_or(Error::Decoding)?);
            i += data_len;
        }

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

#[derive(Default)]
struct Sink;

impl AddAssign<&str> for Sink {
    fn add_assign(&mut self, _other: &str) {}
}

fn try_parse_answer(buffer: &[u8], offset: &mut usize) -> Option<(u32, usize)> {
    // we only have one question, so this name
    // can only be the one our question is about
    let _name: Sink = name_at(buffer, offset)?;
    *offset += 4; // skip qtype, qclass

    let a = *buffer.get(*offset + 0)?;
    let b = *buffer.get(*offset + 1)?;
    let c = *buffer.get(*offset + 2)?;
    let d = *buffer.get(*offset + 3)?;
    let ttl = u32::from_be_bytes([a, b, c, d]);

    let a = *buffer.get(*offset + 4)?;
    let b = *buffer.get(*offset + 5)?;
    let data_len = u16::from_be_bytes([a, b]);
    *offset += 6;

    Some((ttl, data_len as usize))
}

#[derive(Debug)]
struct LabelData<'a> {
    next_label: usize,
    next_field: usize,
    string: &'a str,
}

fn label_at(buf: &[u8], mut offset: usize) -> Option<LabelData<'_>> {
    let mut len_byte = *buf.get(offset)? as usize;
    let mut next_field = usize::MAX;

    if len_byte > 63 {
        next_field = offset + 2;
        let b2 = *buf.get(offset + 1)? as usize;
        offset = ((len_byte & 0x3f) << 8) | b2;

        len_byte = *buf.get(offset)? as usize;
        if len_byte > 63 {
            return None;
        }
    }

    let start = offset + 1;
    let stop = start + len_byte as usize;
    let next_label = stop;

    if next_field == usize::MAX {
        next_field = stop;
    }

    let bytes = buf.get(start..stop)?;

    let data = LabelData {
        next_label,
        next_field,
        string: from_utf8(bytes).ok()?,
    };

    Some(data)
}

fn name_at<T: Default + for<'a> AddAssign<&'a str>>(buf: &[u8], offset: &mut usize) -> Option<T> {
    let mut name = T::default();
    let mut has_jumped = false;
    let mut first_part = true;
    let mut next_field = 0;

    loop {
        let data = label_at(buf, *offset)?;

        if !has_jumped {
            next_field = data.next_field;
        }

        if data.next_label != data.next_field {
            has_jumped = true;
        }

        if data.string.is_empty() {
            *offset = next_field;
            break Some(name);
        }

        if !first_part {
            name += ".";
        }

        name += data.string;
        *offset = data.next_label;
        first_part = false;
    }
}

fn get_ipv4(value: &mut CacheValue) -> &mut Option<Records<Ipv4Addr>> { &mut value.ipv4 }
fn get_ipv6(value: &mut CacheValue) -> &mut Option<Records<Ipv6Addr>> { &mut value.ipv6 }
fn get_cname(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.cname }
fn get_mail(value: &mut CacheValue) -> &mut Option<Records<MailServer>> { &mut value.mail }
fn get_text(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.text }
fn get_name(value: &mut CacheValue) -> &mut Option<Records<String>> { &mut value.name }

fn proc_ipv4(buffer: &[u8], start: usize, len: usize) -> Option<Ipv4Addr> {
    let stop = start + len;
    let data = buffer.get(start..stop)?;
    let quad = <[u8; 4]>::try_from(data).ok()?;
    Some(quad.into())
}

fn proc_ipv6(buffer: &[u8], start: usize, len: usize) -> Option<Ipv6Addr> {
    let stop = start + len;
    let data = buffer.get(start..stop)?;
    let quad = <[u8; 16]>::try_from(data).ok()?;
    Some(quad.into())
}

fn proc_mail(buffer: &[u8], start: usize, len: usize) -> Option<MailServer> {
    let (a, b) = (*buffer.get(start)?, *buffer.get(start + 1)?);
    let preference = u16::from_be_bytes([a, b]);

    let mut offset = start + 2;
    let host = name_at(buffer, &mut offset)?;

    if start + len != offset {
        return None;
    }

    Some(MailServer {
        preference,
        host,
    })
}

fn proc_text(buffer: &[u8], mut offset: usize, mut total: usize) -> Option<String> {
    let mut string = String::new();

    while total > 0 {
        let len_byte = *buffer.get(offset)? as usize;
        let start = offset + 1;
        offset = start + len_byte;
        let bytes = buffer.get(start..offset)?;
        string += from_utf8(bytes).ok()?;
        total = total.checked_sub(len_byte + 1)?;
    }

    Some(string)
}

fn proc_name(buffer: &[u8], start: usize, len: usize) -> Option<String> {
    let mut offset = start;
    let name = name_at(buffer, &mut offset)?;
    let checks_out = start + len == offset;
    checks_out.then_some(name)
}
