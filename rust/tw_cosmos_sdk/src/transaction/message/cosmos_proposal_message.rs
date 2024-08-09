// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2023 Your Name.

use crate::address::CosmosAddress;
use crate::proto::cosmos;
use crate::transaction::message::{CosmosMessage, ProtobufMessage};
use tw_coin_entry::error::prelude::*;
use tw_proto::to_any;

pub struct MsgProposalMessage<Address: CosmosAddress> {
    pub authority: Address,
    pub type_pb: String,
    pub content: MsgProposalMessageContent,
}

pub struct MsgProposalMessageContent {
    pub type_pb: String,
    pub title: String,
    pub description: String,
}

pub struct MsgProposal<Address: CosmosAddress> {
    pub title: String,
    pub deposit: String,
    pub summary: String,
    pub messages: Vec<MsgProposalMessage<Address>>,
}

impl<Address: CosmosAddress> CosmosMessage for MsgProposal<Address> {
    fn to_proto(&self) -> SigningResult<ProtobufMessage> {
        let proto_msg = cosmos::gov::v1beta1::MsgProposal {
            title: self.title.clone(),
            deposit: self.deposit.clone(),
            summary: self.summary.clone(),
            messages: self
                .messages
                .iter()
                .map(|msg| cosmos::gov::v1beta1::mod_MsgProposal::MsgProposalMessage {
                    authority: msg.authority.to_string(),
                    type_pb: msg.type_pb.clone(),
                    content: Some(cosmos::gov::v1beta1::mod_MsgProposal::mod_MsgProposalMessage::MsgProposalMessageContent {
                        type_pb: msg.content.type_pb.clone(),
                        title: msg.content.title.clone(),
                        description: msg.content.description.clone(),
                    }),
                })
                .collect(),
        };

        Ok(to_any(&proto_msg))
    }
}
