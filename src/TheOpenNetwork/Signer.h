// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#pragma once

#include "Data.h"
#include "PrivateKey.h"
#include "wallet/Wallet.h"

#include "proto/TheOpenNetwork.pb.h"

namespace TW::TheOpenNetwork {

/// Helper class that performs TheOpenNetwork transaction signing.
class Signer {
public:
    /// Hide default constructor
    Signer() = delete;

    /// Creates a signed transfer message
    static Data createTransferMessage(std::shared_ptr<Wallet> wallet, const PrivateKey& privateKey, const Proto::Transfer& transfer);

    /// Creates a transfer message preimage for TSS
    static Data createTransferMessageForTSS(std::shared_ptr<Wallet> wallet, const Proto::Transfer& transfer);

    /// Creates a signed jetton transfer message
    static Data createJettonTransferMessage(std::shared_ptr<Wallet> wallet, const PrivateKey& privateKey, const Proto::JettonTransfer& transfer);

    /// Creates a jetton transfer message preimage for TSS
    static Data createJettonTransferMessageForTSS(std::shared_ptr<Wallet> wallet, const Proto::JettonTransfer& jettonTransfer);

    /// Signs a Proto::SigningInput transaction with a private key
    static Proto::SigningOutput sign(const Proto::SigningInput& input) noexcept;

    /// Signs a Proto::SigningInput transaction with TSS signature
    static Proto::SigningOutput sign(const Proto::SigningInput& input, const Data& tssSignature, const PublicKey& fromPublicKey) noexcept;

    /// Generates a pre-image for signing
    static Data signaturePreimage(const Proto::SigningInput& input);

    /// Generates a pre-image and returns the hash and pre-image data for signing
    static void signPreimage(const Proto::SigningInput& input, Data& preImage, Data& preImageHash);

private:
    static void appendTransferToPreimage(const Proto::Transfer& transfer, Data& preImage);
    static void appendJettonTransferToPreimage(const Proto::JettonTransfer& jettonTransfer, Data& preImage);

    template <typename T>
    static void appendData(Data& preImage, const T& value);

    static Data hash(const Data& payload);
};

// Specializations of appendData template
template <>
void Signer::appendData(Data& preImage, const std::string& value);

template <>
void Signer::appendData(Data& preImage, const uint64_t& value);

template <>
void Signer::appendData(Data& preImage, const Data& value);

template <>
void Signer::appendData(Data& preImage, const unsigned char& value);

template <>
void Signer::appendData(Data& preImage, const unsigned int& value);

} // namespace TW::TheOpenNetwork
