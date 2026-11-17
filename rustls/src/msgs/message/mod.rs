use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertLevel, KeyUpdateRequest};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};

mod inbound;
pub use inbound::{BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage};

mod outbound;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Serialized handshake bytes retain their bounded backing through every alias.
#[derive(Clone, Debug)]
pub struct EncodedPayload<'a>(EncodedBacking<'a>);

#[derive(Clone, Debug)]
enum EncodedBacking<'a> {
    Plain(Payload<'a>),
    Bounded(Arc<crate::output_storage::OutputBuffer>),
    Ticket(Arc<crate::TicketBuffer>),
}

impl EncodedPayload<'_> {
    pub(crate) fn ticket(bytes: crate::TicketBuffer) -> Self {
        Self(EncodedBacking::Ticket(Arc::new(bytes)))
    }

    pub(crate) fn bytes_mut(&mut self) -> Option<&mut [u8]> {
        match &mut self.0 {
            EncodedBacking::Plain(Payload::Owned(bytes)) => Some(bytes),
            EncodedBacking::Plain(Payload::Borrowed(_)) => None,
            EncodedBacking::Bounded(bytes) => Arc::get_mut(bytes).map(|bytes| &mut **bytes),
            EncodedBacking::Ticket(bytes) => Arc::get_mut(bytes).map(AsMut::as_mut),
        }
    }
    pub(crate) fn bounded(bytes: crate::output_storage::OutputBuffer) -> Self {
        Self(EncodedBacking::Bounded(Arc::new(bytes)))
    }
    /// Borrow the encoded bytes without separating them from their retained backing.
    pub fn bytes(&self) -> &[u8] {
        match &self.0 {
            EncodedBacking::Plain(p) => p.bytes(),
            EncodedBacking::Bounded(p) => p.as_ref().as_ref(),
            EncodedBacking::Ticket(p) => p.as_ref().as_ref(),
        }
    }
    /// Own borrowed input, or preserve an existing bounded owner without copying it.
    pub fn into_owned(self) -> EncodedPayload<'static> {
        EncodedPayload(match self.0 {
            EncodedBacking::Plain(p) => EncodedBacking::Plain(p.into_owned()),
            EncodedBacking::Bounded(p) => EncodedBacking::Bounded(p),
            EncodedBacking::Ticket(p) => EncodedBacking::Ticket(p),
        })
    }
}
impl<'a> From<Payload<'a>> for EncodedPayload<'a> {
    fn from(payload: Payload<'a>) -> Self {
        Self(EncodedBacking::Plain(payload))
    }
}

pub(crate) use outbound::read_opaque_message_header;
pub use outbound::{OutboundChunks, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload};

#[derive(Debug)]
pub enum MessagePayload<'a> {
    Alert(AlertMessagePayload),
    // one handshake message, parsed
    Handshake {
        parsed: HandshakeMessagePayload<'a>,
        encoded: EncodedPayload<'a>,
    },
    // (potentially) multiple handshake messages, unparsed
    HandshakeFlight(EncodedPayload<'a>),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub fn encode(&self, bytes: &mut dyn crate::msgs::codec::Encoder) {
        match self {
            Self::Alert(x) => x.encode(bytes),
            Self::Handshake { encoded, .. } => bytes.extend_from_slice(encoded.bytes()),
            Self::HandshakeFlight(x) => bytes.extend_from_slice(x.bytes()),
            Self::ChangeCipherSpec(x) => x.encode(bytes),
            Self::ApplicationData(x) => x.encode(bytes),
        }
    }

    pub fn handshake(parsed: HandshakeMessagePayload<'a>) -> Self {
        Self::Handshake {
            encoded: Payload::new(parsed.get_encoding()).into(),
            parsed,
        }
    }

    pub fn new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: &'a [u8],
    ) -> Result<Self, InvalidMessage> {
        let mut r = Reader::init(payload);
        match typ {
            ContentType::ApplicationData => Ok(Self::ApplicationData(Payload::Borrowed(payload))),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers).map(|parsed| Self::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(payload).into(),
                })
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake { .. } | Self::HandshakeFlight(_) => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    pub(crate) fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;
        match self {
            Alert(x) => Alert(x),
            Handshake { parsed, encoded } => Handshake {
                parsed: parsed.into_owned(),
                encoded: encoded.into_owned(),
            },
            HandshakeFlight(x) => HandshakeFlight(x.into_owned()),
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            ApplicationData(x) => ApplicationData(x.into_owned()),
        }
    }
}

impl From<Message<'_>> for PlainMessage {
    fn from(msg: Message<'_>) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload.into_owned(),
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload::Owned(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload<'static>,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OutboundOpaqueMessage {
        OutboundOpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: PrefixedPayload::from(self.payload.bytes()),
        }
    }

    pub fn borrow_inbound(&self) -> InboundPlainMessage<'_> {
        InboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes(),
        }
    }

    pub fn borrow_outbound(&self) -> OutboundPlainMessage<'_> {
        OutboundPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload.bytes().into(),
        }
    }
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message<'a> {
    pub version: ProtocolVersion,
    pub payload: MessagePayload<'a>,
}

impl Message<'_> {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake { parsed, .. } = &self.payload {
            parsed.0.handshake_type() == hstyp
        } else {
            false
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
            )),
        }
    }

    pub fn build_key_update_request() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateRequested),
            )),
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_wire_bytes(self) -> Vec<u8> {
        PlainMessage::from(self)
            .into_unencrypted_opaque()
            .encode()
    }
}

impl TryFrom<PlainMessage> for Message<'static> {
    type Error = InvalidMessage;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload.bytes())?
                .into_owned(),
        })
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`InboundOpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl<'a> TryFrom<InboundPlainMessage<'a>> for Message<'a> {
    type Error = InvalidMessage;

    fn try_from(plain: InboundPlainMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
}

/// Content type, version and size.
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;

/// Maximum message payload size.
/// That's 2^14 payload bytes and a 2KB allowance for ciphertext overheads.
const MAX_PAYLOAD: u16 = 16_384 + 2048;

/// Maximum on-the-wire message size.
#[cfg(feature = "std")]
pub(crate) const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;
