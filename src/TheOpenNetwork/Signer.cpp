// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include "Signer.h"

#include "Base64.h"
#include "TheOpenNetwork/Payloads.h"
#include "TheOpenNetwork/wallet/WalletV4R2.h"
#include "WorkchainType.h"
#include "../Hash.h"
#include <cstring> // For memcpy

namespace TW::TheOpenNetwork {

static constexpr size_t hashThreshold = 256;

Data Signer::createTransferMessage(std::shared_ptr<Wallet> wallet, const PrivateKey& privateKey, const Proto::Transfer& transfer) {
    const auto msg = wallet->createTransferMessage(
        privateKey,
        Address(transfer.dest(), transfer.bounceable()),
        transfer.amount(),
        transfer.sequence_number(),
        static_cast<uint8_t>(transfer.mode()),
        transfer.expire_at(),
        transfer.comment());

    Data result{};
    msg->serialize(result);
    return result;
}

Data Signer::createTransferMessageForTSS(std::shared_ptr<Wallet> wallet, const Proto::Transfer& transfer) {
    const auto msg = wallet->createSigningMessageForTSS(
        Address(transfer.dest(), transfer.bounceable()),
        transfer.amount(),
        transfer.sequence_number(),
        static_cast<uint8_t>(transfer.mode()),
        transfer.expire_at(),
        transfer.comment());

    Data result{};
    msg->serialize(result);
    return result;
}

Data Signer::createJettonTransferMessage(std::shared_ptr<Wallet> wallet, const PrivateKey& privateKey, const Proto::JettonTransfer& jettonTransfer) {
    const Proto::Transfer& transferData = jettonTransfer.transfer();

    const auto payload = jettonTransferPayload(
        Address(jettonTransfer.response_address()),
        Address(jettonTransfer.to_owner()),
        jettonTransfer.jetton_amount(),
        jettonTransfer.forward_amount(),
        transferData.comment(),
        jettonTransfer.query_id());

    const auto msg = wallet->createQueryMessage(
        privateKey,
        Address(transferData.dest(), transferData.bounceable()),
        transferData.amount(),
        transferData.sequence_number(),
        static_cast<uint8_t>(transferData.mode()),
        payload,
        transferData.expire_at());

    Data result{};
    msg->serialize(result);
    return result;
}

Data Signer::createJettonTransferMessageForTSS(std::shared_ptr<Wallet> wallet, const Proto::JettonTransfer& jettonTransfer) {
    const Proto::Transfer& transferData = jettonTransfer.transfer();

    const auto payload = jettonTransferPayload(
        Address(jettonTransfer.response_address()),
        Address(jettonTransfer.to_owner()),
        jettonTransfer.jetton_amount(),
        jettonTransfer.forward_amount(),
        transferData.comment(),
        jettonTransfer.query_id());

    const auto msg = wallet->createSigningMessageForTSS(
        Address(transferData.dest(), transferData.bounceable()),
        transferData.amount(),
        transferData.sequence_number(),
        static_cast<uint8_t>(transferData.mode()),
        transferData.expire_at(),
        std::string{}); // Empty comment for payload

    Data result{};
    msg->serialize(result);
    return result;
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input) noexcept {
    auto protoOutput = Proto::SigningOutput();

    if (!input.private_key().empty()) {
        const auto& privateKey = PrivateKey(input.private_key());
        const auto& publicKey = privateKey.getPublicKey(TWPublicKeyTypeED25519);

        switch (input.action_oneof_case()) {
        case Proto::SigningInput::ActionOneofCase::kTransfer: {
            const auto& transfer = input.transfer();
            try {
                switch (transfer.wallet_version()) {
                case Proto::WalletVersion::WALLET_V4_R2: {
                    const int8_t workchainId = WorkchainType::Basechain;
                    auto wallet = std::make_shared<WalletV4R2>(publicKey, workchainId);
                    const auto& transferMessage = Signer::createTransferMessage(wallet, privateKey, transfer);
                    protoOutput.set_encoded(TW::Base64::encode(transferMessage));
                    break;
                }
                default:
                    protoOutput.set_error(Common::Proto::Error_invalid_params);
                    protoOutput.set_error_message("Unsupported wallet version");
                    break;
                }
            } catch (...) {
                protoOutput.set_error(Common::Proto::Error_general);
            }
            break;
        }
        case Proto::SigningInput::ActionOneofCase::kJettonTransfer: {
            const auto& jettonTransfer = input.jetton_transfer();
            try {
                switch (jettonTransfer.transfer().wallet_version()) {
                case Proto::WalletVersion::WALLET_V4_R2: {
                    const int8_t workchainId = WorkchainType::Basechain;
                    auto wallet = std::make_shared<WalletV4R2>(publicKey, workchainId);
                    const auto& transferMessage = Signer::createJettonTransferMessage(wallet, privateKey, jettonTransfer);
                    protoOutput.set_encoded(TW::Base64::encode(transferMessage));
                    break;
                }
                default:
                    protoOutput.set_error(Common::Proto::Error_invalid_params);
                    protoOutput.set_error_message("Unsupported wallet version");
                    break;
                }
            } catch (...) {
                protoOutput.set_error(Common::Proto::Error_general);
            }
            break;
        }
        default:
            protoOutput.set_error(Common::Proto::Error_invalid_params);
            protoOutput.set_error_message("Unsupported action");
            break;
        }
    } else if (!input.public_key().empty()) {
        protoOutput.set_error(Common::Proto::Error_invalid_params);
        protoOutput.set_error_message("TSS signing requires a signature");
    } else {
        protoOutput.set_error(Common::Proto::Error_invalid_params);
        protoOutput.set_error_message("Missing private key or public key");
    }

    return protoOutput;
}

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input, const Data& tssSignature, const PublicKey& fromPublicKey) noexcept {
    auto protoOutput = Proto::SigningOutput();

    try {
        switch (input.action_oneof_case()) {
        case Proto::SigningInput::ActionOneofCase::kTransfer: {
            const auto& transfer = input.transfer();
            const int8_t workchainId = WorkchainType::Basechain;
            auto wallet = std::make_shared<WalletV4R2>(fromPublicKey, workchainId);

            const auto msg = wallet->createQueryMessageWithSignature(
                tssSignature,
                Address(transfer.dest(), transfer.bounceable()),
                transfer.amount(),
                transfer.sequence_number(),
                static_cast<uint8_t>(transfer.mode()),
                nullptr, // Assuming payload is null
                transfer.expire_at());
            Data result{};
            msg->serialize(result);
            protoOutput.set_encoded(TW::Base64::encode(result));
            break;
        }
        case Proto::SigningInput::ActionOneofCase::kJettonTransfer: {
            const auto& jettonTransfer = input.jetton_transfer();
            const int8_t workchainId = WorkchainType::Basechain;
            auto wallet = std::make_shared<WalletV4R2>(fromPublicKey, workchainId);

            const Proto::Transfer& transferData = jettonTransfer.transfer();
            const auto payload = jettonTransferPayload(
                Address(jettonTransfer.response_address()),
                Address(jettonTransfer.to_owner()),
                jettonTransfer.jetton_amount(),
                jettonTransfer.forward_amount(),
                transferData.comment(),
                jettonTransfer.query_id());
            const auto msg = wallet->createQueryMessageWithSignature(
                tssSignature,
                Address(transferData.dest(), transferData.bounceable()),
                transferData.amount(),
                transferData.sequence_number(),
                static_cast<uint8_t>(transferData.mode()),
                payload,
                transferData.expire_at());
            Data result{};
            msg->serialize(result);
            protoOutput.set_encoded(TW::Base64::encode(result));
            break;
        }
        default:
            protoOutput.set_error(Common::Proto::Error_invalid_params);
            protoOutput.set_error_message("Unsupported action");
            break;
        }
    } catch (...) {
        protoOutput.set_error(Common::Proto::Error_general);
    }

    return protoOutput;
}

Data Signer::signaturePreimage(const Proto::SigningInput& input) {
    Data preImage;
    switch (input.action_oneof_case()) {
    case Proto::SigningInput::ActionOneofCase::kTransfer: {
        const auto& transfer = input.transfer();
        appendTransferToPreimage(transfer, preImage);
        break;
    }
    case Proto::SigningInput::ActionOneofCase::kJettonTransfer: {
        const auto& jettonTransfer = input.jetton_transfer();
        appendJettonTransferToPreimage(jettonTransfer, preImage);
        break;
    }
    default:
        break;
    }
    return preImage;
}

void Signer::signPreimage(const Proto::SigningInput& input, Data& preImage, Data& preImageHash) {
    preImage = signaturePreimage(input);
    preImageHash = hash(preImage);
}

void Signer::appendTransferToPreimage(const Proto::Transfer& transfer, Data& preImage) {
    appendData(preImage, transfer.dest());
    appendData(preImage, transfer.amount());
    appendData(preImage, transfer.sequence_number());
    appendData(preImage, static_cast<uint8_t>(transfer.mode()));
    appendData(preImage, transfer.expire_at());
    appendData(preImage, transfer.comment());
}

void Signer::appendJettonTransferToPreimage(const Proto::JettonTransfer& jettonTransfer, Data& preImage) {
    const Proto::Transfer& transferData = jettonTransfer.transfer();
    appendTransferToPreimage(transferData, preImage);
    appendData(preImage, jettonTransfer.response_address());
    appendData(preImage, jettonTransfer.to_owner());
    appendData(preImage, jettonTransfer.jetton_amount());
    appendData(preImage, jettonTransfer.forward_amount());
    appendData(preImage, jettonTransfer.query_id());
}

template <>
void Signer::appendData(Data& preImage, const std::string& value) {
    preImage.insert(preImage.end(), value.begin(), value.end());
}

template <>
void Signer::appendData(Data& preImage, const uint64_t& value) {
    Data buffer(8);
    buffer[0] = (value >> 56) & 0xFF;
    buffer[1] = (value >> 48) & 0xFF;
    buffer[2] = (value >> 40) & 0xFF;
    buffer[3] = (value >> 32) & 0xFF;
    buffer[4] = (value >> 24) & 0xFF;
    buffer[5] = (value >> 16) & 0xFF;
    buffer[6] = (value >> 8) & 0xFF;
    buffer[7] = value & 0xFF;
    preImage.insert(preImage.end(), buffer.begin(), buffer.end());
}

template <>
void Signer::appendData(Data& preImage, const Data& value) {
    preImage.insert(preImage.end(), value.begin(), value.end());
}

template <>
void Signer::appendData(Data& preImage, const unsigned char& value) {
    preImage.push_back(value);
}

template <>
void Signer::appendData(Data& preImage, const unsigned int& value) {
    Data buffer(4);
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
    preImage.insert(preImage.end(), buffer.begin(), buffer.end());
}

Data Signer::hash(const Data& payload) {
    // Using SHA-256 for hashing
    return Hash::sha256(payload);
}

} // namespace TW::TheOpenNetwork
