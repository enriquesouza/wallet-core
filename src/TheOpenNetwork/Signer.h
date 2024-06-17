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

    /// Creates a signed jetton transfer message
    static Data createJettonTransferMessage(std::shared_ptr<Wallet> wallet, const PrivateKey& privateKey, const Proto::JettonTransfer& transfer);

    /// Signs a Proto::SigningInput transaction
    static Proto::SigningOutput sign(const Proto::SigningInput& input) noexcept;

    /// Creates a pre-image for signing
    static Data signaturePreimage(const Proto::SigningInput& input);

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
