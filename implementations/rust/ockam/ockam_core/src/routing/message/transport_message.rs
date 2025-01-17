use crate::errcode::{Kind, Origin};
#[cfg(feature = "std")]
use crate::OpenTelemetryContext;
#[cfg(feature = "tracing_context")]
use crate::OCKAM_TRACER_NAME;
use crate::{compat::vec::Vec, Decodable, Encodable, Encoded, Message, Route};
use cfg_if::cfg_if;
use core::fmt::{self, Display, Formatter};
#[cfg(feature = "tracing_context")]
use opentelemetry::{
    global,
    trace::{Link, SpanBuilder, TraceContextExt, Tracer},
    Context,
};

/// A generic transport message type.
///
/// This type is exposed in `ockam_core` (and the root `ockam` crate) in
/// order to provide a mechanism for third-party developers to create
/// custom transport channel routers.
///
/// Casual users of Ockam should never have to interact with this type
/// directly.
///
/// # Examples
///
/// See `ockam_transport_tcp::workers::sender::TcpSendWorker` for a usage example.
///
#[derive(Debug, Clone, Eq, PartialEq, Message)]
pub struct TransportMessage {
    /// The transport protocol version.
    pub version: u8,
    /// Onward message route.
    pub onward_route: Route,
    /// Return message route.
    ///
    /// This field must be populated by routers handling this message
    /// along the way.
    pub return_route: Route,
    /// The message payload.
    pub payload: Vec<u8>,
    /// An optional tracing context
    #[cfg(feature = "tracing_context")]
    pub tracing_context: Option<String>,
}

impl TransportMessage {
    /// Create a new v1 transport message with empty return route.
    pub fn v1(
        onward_route: impl Into<Route>,
        return_route: impl Into<Route>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: 1,
            onward_route: onward_route.into(),
            return_route: return_route.into(),
            payload,
            #[cfg(feature = "tracing_context")]
            tracing_context: None,
        }
    }

    /// Return a TransportMessage with a new tracing context:
    ///    - A new trace is started
    ///    - The previous trace and the new trace are linked together
    ///
    /// We start a new trace here in order to make sure that each transport message is always
    /// associated to a globally unique trace id and then cannot be correlated with another transport
    /// message that would leave the same node for example.
    ///
    /// We can still navigate the two created traces as one thanks to their link.
    #[cfg(feature = "std")]
    pub fn start_new_tracing_context(self, _tracing_context: OpenTelemetryContext) -> Self {
        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                // start a new trace for this transport message, and link it to the previous trace, via the current tracing context
                let tracer = global::tracer(OCKAM_TRACER_NAME);
                let span_builder = SpanBuilder::from_name("TransportMessage::start_trace")
                      .with_links(vec![Link::new(_tracing_context.extract().span().span_context().clone(), vec![])]);
                let span = tracer.build_with_context(span_builder, &Context::default());
                let cx = Context::current_with_span(span);

                // create a span to close the previous trace and link it to the new trace
                let span_builder = SpanBuilder::from_name("TransportMessage::end_trace")
                                 .with_links(vec![Link::new(cx.span().span_context().clone(), vec![])]);
                let _ = tracer.build_with_context(span_builder, &_tracing_context.extract());

                // create the new opentelemetry context
                let tracing_context = OpenTelemetryContext::inject(&cx);

                Self {
                    tracing_context: Some(tracing_context.to_string()),
                    ..self
                }
            } else {
                self
            }
        }
    }

    /// Return the tracing context
    #[cfg(feature = "tracing_context")]
    pub fn tracing_context(&self) -> OpenTelemetryContext {
        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                match self.tracing_context.as_ref() {
                    Some(tracing_context) => OpenTelemetryContext::from_remote_context(tracing_context),
                    None => OpenTelemetryContext::current(),
                }
            } else {
                OpenTelemetryContext::current()
            }
        }
    }
}

impl Display for TransportMessage {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Message (onward route: {}, return route: {})",
            self.onward_route, self.return_route
        )
    }
}

impl Encodable for TransportMessage {
    fn encode(self) -> crate::Result<Encoded> {
        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                let tracing = if let Some(tracing_context) = self.tracing_context {
                    1 + crate::bare::size_of_slice(tracing_context)
                } else {
                    1
                };
            } else {
                let tracing = 0;
            }
        };

        let mut encoded = Vec::with_capacity(
            1 + self.onward_route.encoded_size()
                + self.return_route.encoded_size()
                + crate::bare::size_of_slice(&self.payload)
                + tracing,
        );
        encoded.push(self.version);
        self.onward_route.manual_encode(&mut encoded);
        self.return_route.manual_encode(&mut encoded);
        crate::bare::write_slice(&mut encoded, &self.payload);
        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                if let Some(tracing_context) = self.tracing_context {
                    vec.push(1);
                    crate::bare::write_str(&mut encoded, &tracing_context);
                }
                else {
                    encoded.push(0);
                }
            }
        }
        Ok(encoded)
    }
}

impl Decodable for TransportMessage {
    fn decode(slice: &[u8]) -> crate::Result<Self> {
        Self::internal_decode(slice).ok_or_else(|| {
            crate::Error::new(
                Origin::Transport,
                Kind::Protocol,
                "Failed to decode TransportMessage",
            )
        })
    }
}

impl TransportMessage {
    fn internal_decode(slice: &[u8]) -> Option<Self> {
        let mut index = 0;
        let version = slice.get(index)?;
        index += 1;

        let onward_route = Route::manual_decode(slice, &mut index)?;
        let return_route = Route::manual_decode(slice, &mut index)?;
        let payload = crate::bare::read_slice(slice, &mut index)?;

        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                // ignore if missing, keep compatibility with older messages
                let present = slice.get(index).unwrap_or(0);
                index += 1;
                let tracing_context = if present == 1 {
                    crate::bare::read_str(slice, &mut index).map(|s| s.to_string())
                } else {
                    None
                };

                Some(Self {
                    version: *version,
                    onward_route,
                    return_route,
                    payload: payload.to_vec(),
                    tracing_context
                })
            } else {
                Some(Self {
                    version: *version,
                    onward_route,
                    return_route,
                    payload: payload.to_vec(),
                })
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{route, Decodable, Encodable};
    use serde::Serialize;

    #[derive(Debug, Clone, Eq, PartialEq, Serialize)]
    pub struct TransportMessageWithoutTracing {
        /// The transport protocol version.
        pub version: u8,
        /// Onward message route.
        pub onward_route: Route,
        /// Return message route.
        ///
        /// This field must be populated by routers handling this message
        /// along the way.
        pub return_route: Route,
        /// The message payload.
        pub payload: Vec<u8>,
    }

    #[test]
    fn encode_decode_transport_message() {
        let msg = TransportMessage::v1(
            route!["onward", "route!"],
            route!["return", "route!"],
            "hello".as_bytes().to_vec(),
        );

        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                msg.tracing_context = Some("tracing context".to_string());
            }
        }
        let encoded = msg.clone().encode().unwrap();
        let decoded = TransportMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn can_decode_older_serialized_version() {
        let msg = TransportMessageWithoutTracing {
            version: 1,
            onward_route: route!["onward", "route!"],
            return_route: route!["return", "route!"],
            payload: "hello".as_bytes().to_vec(),
        };

        let encoded = msg.clone().encode().unwrap();
        let decoded = TransportMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.onward_route, route!["onward", "route!"]);
        assert_eq!(decoded.return_route, route!["return", "route!"]);
        assert_eq!(decoded.payload, "hello".as_bytes().to_vec());
        cfg_if! {
            if #[cfg(feature = "tracing_context")] {
                assert!(decoded.tracing_context.is_none());
            }
        }
    }
}
