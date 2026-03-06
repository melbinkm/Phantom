#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
gen_nft_seeds.py — Generate seed corpus for nf_tables fuzzing.

Creates binary files containing valid nfnetlink messages for the
nf_tables subsystem. These serve as initial seeds for mutation-based
fuzzing via Phantom.

Usage:
    python3 gen_nft_seeds.py [output_dir]
"""
import os
import struct
import sys

# Netlink constants
NLM_F_REQUEST = 0x0001
NLM_F_ACK = 0x0004
NLM_F_CREATE = 0x0400
NLM_F_EXCL = 0x0200

# nfnetlink
NFNL_SUBSYS_NFTABLES = 10

# nf_tables message types
NFT_MSG_NEWTABLE = 0
NFT_MSG_GETTABLE = 1
NFT_MSG_DELTABLE = 2
NFT_MSG_NEWCHAIN = 3
NFT_MSG_GETCHAIN = 4
NFT_MSG_DELCHAIN = 5
NFT_MSG_NEWRULE = 6
NFT_MSG_GETRULE = 7
NFT_MSG_DELRULE = 8
NFT_MSG_NEWSET = 9
NFT_MSG_GETSET = 10
NFT_MSG_DELSET = 11
NFT_MSG_NEWSETELEM = 12
NFT_MSG_GETSETELEM = 13
NFT_MSG_DELSETELEM = 14
NFT_MSG_NEWOBJ = 18
NFT_MSG_GETOBJ = 19
NFT_MSG_DELOBJ = 20

# nf_tables attributes
NFTA_TABLE_NAME = 1
NFTA_TABLE_FLAGS = 2
NFTA_CHAIN_TABLE = 1
NFTA_CHAIN_NAME = 3
NFTA_CHAIN_HOOK = 4
NFTA_CHAIN_POLICY = 5
NFTA_CHAIN_TYPE = 7
NFTA_HOOK_HOOKNUM = 1
NFTA_HOOK_PRIORITY = 2
NFTA_RULE_TABLE = 1
NFTA_RULE_CHAIN = 2
NFTA_RULE_EXPRESSIONS = 4
NFTA_LIST_ELEM = 1
NFTA_EXPR_NAME = 1
NFTA_EXPR_DATA = 2
NFTA_SET_TABLE = 1
NFTA_SET_NAME = 2
NFTA_SET_KEY_TYPE = 4
NFTA_SET_KEY_LEN = 5
NFTA_SET_DATA_TYPE = 6
NFTA_SET_DATA_LEN = 7
NFTA_SET_FLAGS = 3
NFTA_SET_ELEM_LIST_TABLE = 1
NFTA_SET_ELEM_LIST_SET = 2
NFTA_SET_ELEM_LIST_ELEMENTS = 3
NFTA_SET_ELEM_KEY = 1
NFTA_SET_ELEM_DATA = 2

# nf_tables hook numbers
NF_INET_PRE_ROUTING = 0
NF_INET_LOCAL_IN = 1
NF_INET_FORWARD = 2
NF_INET_LOCAL_OUT = 3
NF_INET_POST_ROUTING = 4

# Address families
AF_INET = 2
NFPROTO_INET = 1
NFPROTO_IPV4 = 2

# NFNETLINK version
NFNETLINK_V0 = 0

# NF accept/drop
NF_DROP = 0
NF_ACCEPT = 1


def nlattr(nla_type, data):
    """Build a netlink attribute (NLA)."""
    if isinstance(data, str):
        data = data.encode() + b'\x00'
    nla_len = 4 + len(data)
    # Pad to 4-byte alignment
    padded = data + b'\x00' * ((4 - len(data) % 4) % 4)
    return struct.pack('HH', nla_len, nla_type) + padded


def nlattr_nested(nla_type, *children):
    """Build a nested netlink attribute."""
    payload = b''.join(children)
    nla_len = 4 + len(payload)
    return struct.pack('HH', nla_len, nla_type | 0x8000) + payload


def nlattr_u32(nla_type, val):
    """Build a u32 netlink attribute."""
    return nlattr(nla_type, struct.pack('!I', val))


def nfnl_msg(msg_type, family, flags, attrs):
    """Build a complete nfnetlink message."""
    nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | msg_type
    # nfgenmsg header
    nfgen = struct.pack('BBH', family, NFNETLINK_V0, 0)
    payload = nfgen + b''.join(attrs)
    nlmsg_len = 16 + len(payload)  # nlmsghdr(16) + payload
    nlh = struct.pack('IHHII', nlmsg_len, nlmsg_type,
                      NLM_F_REQUEST | flags, 1, 0)
    return nlh + payload


def batch_begin():
    """NFNL_MSG_BATCH_BEGIN message."""
    nlmsg_type = (0x10 << 8)  # NFNL_SUBSYS_NONE << 8 | NFNL_MSG_BATCH_BEGIN
    nfgen = struct.pack('BBH', AF_INET, NFNETLINK_V0, 0x0a)  # res_id=NFNL_SUBSYS_NFTABLES
    nlmsg_len = 16 + len(nfgen)
    return struct.pack('IHHII', nlmsg_len, nlmsg_type,
                       NLM_F_REQUEST, 0, 0) + nfgen


def batch_end():
    """NFNL_MSG_BATCH_END message."""
    nlmsg_type = (0x10 << 8) | 1  # NFNL_SUBSYS_NONE << 8 | NFNL_MSG_BATCH_END
    nfgen = struct.pack('BBH', AF_INET, NFNETLINK_V0, 0x0a)
    nlmsg_len = 16 + len(nfgen)
    return struct.pack('IHHII', nlmsg_len, nlmsg_type,
                       NLM_F_REQUEST, 0, 0) + nfgen


def seed_newtable(name='fuzz', family=NFPROTO_IPV4):
    """NFT_MSG_NEWTABLE — create a table."""
    return nfnl_msg(NFT_MSG_NEWTABLE, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_TABLE_NAME, name)])


def seed_newchain_base(table='fuzz', name='input', hooknum=NF_INET_LOCAL_IN,
                       prio=0, family=NFPROTO_IPV4):
    """NFT_MSG_NEWCHAIN — create a base chain with hook."""
    hook = nlattr_nested(NFTA_CHAIN_HOOK,
                         nlattr_u32(NFTA_HOOK_HOOKNUM, hooknum),
                         nlattr_u32(NFTA_HOOK_PRIORITY, prio))
    return nfnl_msg(NFT_MSG_NEWCHAIN, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_CHAIN_TABLE, table),
                     nlattr(NFTA_CHAIN_NAME, name),
                     hook,
                     nlattr_u32(NFTA_CHAIN_POLICY, NF_ACCEPT),
                     nlattr(NFTA_CHAIN_TYPE, 'filter')])


def seed_newrule_counter(table='fuzz', chain='input', family=NFPROTO_IPV4):
    """NFT_MSG_NEWRULE — simple rule with counter expression."""
    expr_counter = nlattr_nested(NFTA_LIST_ELEM,
                                 nlattr(NFTA_EXPR_NAME, 'counter'))
    exprs = nlattr_nested(NFTA_RULE_EXPRESSIONS, expr_counter)
    return nfnl_msg(NFT_MSG_NEWRULE, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_RULE_TABLE, table),
                     nlattr(NFTA_RULE_CHAIN, chain),
                     exprs])


def seed_newrule_payload_cmp(table='fuzz', chain='input', family=NFPROTO_IPV4):
    """NFT_MSG_NEWRULE — rule with payload + cmp expressions."""
    # payload expression: load 4 bytes from network header offset 12 (src ip)
    expr_payload = nlattr_nested(NFTA_LIST_ELEM,
                                 nlattr(NFTA_EXPR_NAME, 'payload'),
                                 nlattr_nested(NFTA_EXPR_DATA,
                                               nlattr_u32(1, 1),    # NFTA_PAYLOAD_BASE=network
                                               nlattr_u32(2, 12),   # NFTA_PAYLOAD_OFFSET=12
                                               nlattr_u32(3, 4),    # NFTA_PAYLOAD_LEN=4
                                               nlattr_u32(4, 0)))   # NFTA_PAYLOAD_DREG=0
    # cmp expression: compare register 0 == 0x0a000001 (10.0.0.1)
    cmp_data = nlattr(2, struct.pack('!I', 0x0a000001))  # NFTA_CMP_DATA
    expr_cmp = nlattr_nested(NFTA_LIST_ELEM,
                             nlattr(NFTA_EXPR_NAME, 'cmp'),
                             nlattr_nested(NFTA_EXPR_DATA,
                                           nlattr_u32(1, 1),   # NFTA_CMP_SREG=1
                                           nlattr_u32(2, 0),   # NFTA_CMP_OP=eq
                                           cmp_data))
    exprs = nlattr_nested(NFTA_RULE_EXPRESSIONS, expr_payload, expr_cmp)
    return nfnl_msg(NFT_MSG_NEWRULE, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_RULE_TABLE, table),
                     nlattr(NFTA_RULE_CHAIN, chain),
                     exprs])


def seed_newset(table='fuzz', name='myset', family=NFPROTO_IPV4):
    """NFT_MSG_NEWSET — create a set."""
    return nfnl_msg(NFT_MSG_NEWSET, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_SET_TABLE, table),
                     nlattr(NFTA_SET_NAME, name),
                     nlattr_u32(NFTA_SET_KEY_TYPE, 7),   # ipv4_addr
                     nlattr_u32(NFTA_SET_KEY_LEN, 4),
                     nlattr_u32(NFTA_SET_FLAGS, 0)])


def seed_gettable(family=NFPROTO_IPV4):
    """NFT_MSG_GETTABLE — list tables."""
    return nfnl_msg(NFT_MSG_GETTABLE, family, NLM_F_ACK, [])


def seed_deltable(name='fuzz', family=NFPROTO_IPV4):
    """NFT_MSG_DELTABLE — delete a table."""
    return nfnl_msg(NFT_MSG_DELTABLE, family, NLM_F_ACK,
                    [nlattr(NFTA_TABLE_NAME, name)])


def seed_batch_create():
    """Batched: create table + chain + rule."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newrule_counter() +
            batch_end())


def seed_batch_create_delete():
    """Batched: create table, then delete it."""
    return (batch_begin() +
            seed_newtable() +
            seed_deltable() +
            batch_end())


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else 'seeds'
    os.makedirs(outdir, exist_ok=True)

    seeds = {
        'newtable': seed_newtable(),
        'newtable_inet': seed_newtable('inet_tbl', NFPROTO_INET),
        'newchain_base': seed_newchain_base(),
        'newrule_counter': seed_newrule_counter(),
        'newrule_payload_cmp': seed_newrule_payload_cmp(),
        'newset': seed_newset(),
        'gettable': seed_gettable(),
        'deltable': seed_deltable(),
        'batch_create': seed_batch_create(),
        'batch_create_delete': seed_batch_create_delete(),
    }

    for name, data in seeds.items():
        path = os.path.join(outdir, name)
        with open(path, 'wb') as f:
            f.write(data)
        print(f'{path}: {len(data)} bytes')

    print(f'\nGenerated {len(seeds)} seeds in {outdir}/')


if __name__ == '__main__':
    main()
