use stringprep::saslprep;

pub use super::errors::{IntegrityKeyGenerationError, MessageDecodeError, MessageEncodeError};
use crate::definitions::StunTransactionId;
use crate::header::StunHeader;
use crate::header::{StunMessageClass, StunMessageMethod};
use crate::StunAttribute;

use super::message::StunMessage;

impl StunMessage {
    /// Creates a new message
    pub fn new(method: StunMessageMethod, class: StunMessageClass) -> Self {
        let header = StunHeader::new(method, class, None);

        Self {
            header,
            attributes: Vec::new(),
        }
    }

    /// Creates a Binding Request
    pub fn create_request() -> Self {
        Self::default().set_message_class(StunMessageClass::Request)
    }

    /// Creates a Binding Success Response
    pub fn create_success_response() -> Self {
        Self::default().set_message_class(StunMessageClass::SuccessResponse)
    }

    /// Creates a Binding Error Response
    pub fn create_error_response() -> Self {
        Self::default().set_message_class(StunMessageClass::ErrorResponse)
    }

    /// Creates a Binding Indication
    pub fn create_indication() -> Self {
        Self::default().set_message_class(StunMessageClass::Indication)
    }

    /// Sets message transaction id
    pub fn set_transaction_id(mut self, transaction_id: StunTransactionId) -> Self {
        self.header.transaction_id = transaction_id;

        self
    }

    /// Sets message class
    pub fn set_message_class(mut self, class: StunMessageClass) -> Self {
        self.header.message_class = class;

        self
    }

    /// Sets message method
    pub fn set_message_method(mut self, method: StunMessageMethod) -> Self {
        self.header.message_method = method;

        self
    }

    /// Returns an immutable reference to the message header
    pub fn get_header(&self) -> &StunHeader {
        &self.header
    }

    /// Returns an immutable reference to the message attributes
    pub fn get_attributes(&self) -> &Vec<StunAttribute> {
        &self.attributes
    }

    /// Adds an attribute to the list
    pub fn add_attribute(mut self, attr: StunAttribute) -> Self {
        self.attributes.push(attr);

        self
    }

    /// Adds a Fingerprint attribute at the end of the message
    ///
    /// NOTE: This function should be invoked only when all other attributes are added
    pub fn add_fingerprint(mut self) -> Self {
        self.attributes
            .push(StunAttribute::Fingerprint { value: 0 });

        self
    }

    /// Adds a MessageIntegrity attribute at the end of the message
    ///
    /// NOTE: This function should be invoked only when all other attributes are added but before the Fingerprint attribute
    pub fn add_message_integrity(mut self) -> Self {
        self.attributes
            .push(StunAttribute::MessageIntegrity { key: Vec::new() });

        self
    }

    /// Adds USER, REALM and MESSAGE-INTEGRITY attributes for long term credential authentication
    ///
    /// NOTE: This function should be invoked only when all other attributes are added but before the Fingerprint attribute
    pub fn add_long_term_credential_message_integrity(
        mut self,
        username: &str,
        realm: &str,
    ) -> Result<Self, stringprep::Error> {
        self.attributes.push(StunAttribute::Username {
            value: saslprep(username)?.to_string(),
        });

        self.attributes.push(StunAttribute::Realm {
            value: saslprep(realm)?.to_string(),
        });

        Ok(self.add_message_integrity())
    }
}

impl std::default::Default for StunMessage {
    /// Default STUN message.
    ///
    /// Class: Request
    /// Method: Binding
    /// Transaction ID: randomly generated
    fn default() -> Self {
        Self::new(StunMessageMethod::BindingRequest, StunMessageClass::Request)
    }
}
