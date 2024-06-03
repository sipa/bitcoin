// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETMESSAGEMAKER_H
#define BITCOIN_NETMESSAGEMAKER_H

#include <net.h>
#include <protocol.h>
#include <serialize.h>

namespace NetMsg {
    template <typename... Args>
    CSerializedNetMsg Make(std::string msg_type, Args&&... args)
    {
        CSerializedNetMsg msg;
        msg.data.resize(CMessageHeader::COMMAND_SIZE);
        Assume(msg_type.size() <= CMessageHeader::COMMAND_SIZE);
        std::copy(msg_type.begin(), msg_type.end(), msg.data.begin());
        msg.m_type = std::move(msg_type);
        VectorWriter{msg.data, msg.data.size(), std::forward<Args>(args)...};
        return msg;
    }
} // namespace NetMsg

#endif // BITCOIN_NETMESSAGEMAKER_H
