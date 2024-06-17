// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#include "Entry.h"

#include "Address.h"
#include "Signer.h"
#include "TheOpenNetwork/wallet/WalletV4R2.h"
#include "WorkchainType.h"
#include "proto/TransactionCompiler.pb.h"

namespace TW::TheOpenNetwork {

bool Entry::validateAddress([[maybe_unused]] TWCoinType coin, [[maybe_unused]] const std::string& address, [[maybe_unused]] const PrefixVariant& addressPrefix) const {
    return Address::isValid(address);
}

std::string Entry::normalizeAddress([[maybe_unused]] TWCoinType coin, const std::string& address) const {
    return Address(address).string(true, true, false);
}

std::string Entry::deriveAddress([[maybe_unused]] TWCoinType coin, const PublicKey& publicKey, [[maybe_unused]] TWDerivation derivation, [[maybe_unused]] const PrefixVariant& addressPrefix) const {
    return WalletV4R2(publicKey, WorkchainType::Basechain).getAddress().string();
}

void Entry::sign([[maybe_unused]] TWCoinType coin, const TW::Data& dataIn, TW::Data& dataOut) const {
    signTemplate<Signer, Proto::SigningInput>(dataIn, dataOut);
}

TW::Data Entry::preImageHashes([[maybe_unused]] TWCoinType coin, const Data& txInputData) const {
    return txCompilerTemplate<Proto::SigningInput, TxCompiler::Proto::PreSigningOutput>(
        txInputData, [&](const auto& input, auto& output) {
            auto preImage = Signer::signaturePreimage(input);
            auto preImageHash = Hash::sha256(preImage);
            output.set_data_hash(preImageHash.data(), preImageHash.size());
            output.set_data(preImage.data(), preImage.size());
        });
}

void Entry::signPreimage([[maybe_unused]] TWCoinType coin, const Data& txInputData, Data& preImage, Data& preImageHash) const {
    auto input = Proto::SigningInput();
    input.ParseFromArray(txInputData.data(), (int)txInputData.size());
    Signer::signPreimage(input, preImage, preImageHash);
}

void Entry::compile([[maybe_unused]] TWCoinType coin, const Data& txInputData, const std::vector<Data>& signatures, const std::vector<PublicKey>& publicKeys, Data& dataOut) const {
    dataOut = txCompilerTemplate<Proto::SigningInput, TxCompiler::Proto::PreSigningOutput>(
        txInputData, [&](const auto& input, auto& output) {
            if (signatures.size() == 0 || publicKeys.size() == 0) {
                output.set_error(Common::Proto::Error_invalid_params);
                output.set_error_message("empty signatures or public keys");
                return;
            }

            if (signatures.size() != publicKeys.size()) {
                output.set_error(Common::Proto::Error_invalid_params);
                output.set_error_message("signatures size and public keys size not equal");
                return;
            }

            HashPubkeyList externalSignatures;
            auto n = signatures.size();
            for (auto i = 0ul; i < n; ++i) {
                externalSignatures.push_back(std::make_pair(signatures[i], publicKeys[i].bytes));
            }

            // Since signing is done externally, we simply prepare the pre-image data for external signing
            auto preImage = Signer::signaturePreimage(input);
            output.set_data(preImage.data(), preImage.size());
        });
}

} // namespace TW::TheOpenNetwork
