// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#pragma once

#include "CoinEntry.h"

namespace TW::TheOpenNetwork {

class Entry final : public CoinEntry {
public:
    bool validateAddress(TWCoinType coin, const std::string& address, const PrefixVariant& addressPrefix) const;
    std::string normalizeAddress(TWCoinType coin, const std::string& address) const;
    std::string deriveAddress(TWCoinType coin, const PublicKey& publicKey, TWDerivation derivation, const PrefixVariant& addressPrefix) const;
    void sign(TWCoinType coin, const Data& dataIn, Data& dataOut) const;
    Data preImageHashes(TWCoinType coin, const Data& txInputData) const;
    void compile(TWCoinType coin, const Data& txInputData, const std::vector<Data>& signatures, const std::vector<PublicKey>& publicKeys, Data& dataOut) const;
};

} // namespace TW::TheOpenNetwork
