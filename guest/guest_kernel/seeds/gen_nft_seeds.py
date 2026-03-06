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


# -------------------------------------------------------------------
# Multi-step sequences targeting known CVE patterns
# -------------------------------------------------------------------

# Additional NFT message types and constants for CVE-targeting seeds
NFT_MSG_NEWGEN = 16
NFT_MSG_GETGEN = 17
NFT_MSG_NEWFLOWTABLE = 24
NFT_SET_ANONYMOUS = 0x01
NFT_SET_MAP = 0x08
NFTA_VERDICT_CODE = 1
NFTA_IMMEDIATE_DREG = 1
NFTA_IMMEDIATE_DATA = 2
NFTA_DATA_VERDICT = 2
NF_DROP = 0
NF_ACCEPT = 1
NFT_RETURN = -5 & 0xFFFFFFFF  # NF_VERDICT unsigned encoding
NFT_GOTO = -3 & 0xFFFFFFFF
NFT_JUMP = -2 & 0xFFFFFFFF


def seed_newchain_regular(table='fuzz', name='user_chain', family=NFPROTO_IPV4):
    """NFT_MSG_NEWCHAIN — create a regular (non-base) chain."""
    return nfnl_msg(NFT_MSG_NEWCHAIN, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_CHAIN_TABLE, table),
                     nlattr(NFTA_CHAIN_NAME, name)])


def seed_delchain(table='fuzz', name='input', family=NFPROTO_IPV4):
    """NFT_MSG_DELCHAIN — delete a chain."""
    return nfnl_msg(NFT_MSG_DELCHAIN, family, NLM_F_ACK,
                    [nlattr(NFTA_CHAIN_TABLE, table),
                     nlattr(NFTA_CHAIN_NAME, name)])


def seed_newrule_immediate_verdict(table='fuzz', chain='input',
                                   verdict=NF_DROP, family=NFPROTO_IPV4):
    """NFT_MSG_NEWRULE — rule with immediate verdict expression."""
    # immediate expression: set dreg=0 to verdict
    verdict_data = nlattr_nested(NFTA_DATA_VERDICT,
                                 nlattr_u32(NFTA_VERDICT_CODE, verdict))
    expr_imm = nlattr_nested(NFTA_LIST_ELEM,
                             nlattr(NFTA_EXPR_NAME, 'immediate'),
                             nlattr_nested(NFTA_EXPR_DATA,
                                           nlattr_u32(NFTA_IMMEDIATE_DREG, 0),
                                           verdict_data))
    exprs = nlattr_nested(NFTA_RULE_EXPRESSIONS, expr_imm)
    return nfnl_msg(NFT_MSG_NEWRULE, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_RULE_TABLE, table),
                     nlattr(NFTA_RULE_CHAIN, chain),
                     exprs])


def seed_newset_anon(table='fuzz', name='__set0', family=NFPROTO_IPV4):
    """NFT_MSG_NEWSET — create an anonymous set (CVE-2023-32233 pattern)."""
    return nfnl_msg(NFT_MSG_NEWSET, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_SET_TABLE, table),
                     nlattr(NFTA_SET_NAME, name),
                     nlattr_u32(NFTA_SET_KEY_TYPE, 7),
                     nlattr_u32(NFTA_SET_KEY_LEN, 4),
                     nlattr_u32(NFTA_SET_FLAGS, NFT_SET_ANONYMOUS)])


def seed_delset(table='fuzz', name='myset', family=NFPROTO_IPV4):
    """NFT_MSG_DELSET — delete a set."""
    return nfnl_msg(NFT_MSG_DELSET, family, NLM_F_ACK,
                    [nlattr(NFTA_SET_TABLE, table),
                     nlattr(NFTA_SET_NAME, name)])


def seed_newsetelem(table='fuzz', setname='myset', family=NFPROTO_IPV4):
    """NFT_MSG_NEWSETELEM — add elements to a set."""
    elem = nlattr_nested(NFTA_LIST_ELEM,
                         nlattr(NFTA_SET_ELEM_KEY,
                                struct.pack('!I', 0x0a000001)),  # 10.0.0.1
                         nlattr(NFTA_SET_ELEM_DATA,
                                struct.pack('!I', NF_ACCEPT)))
    elems = nlattr_nested(NFTA_SET_ELEM_LIST_ELEMENTS, elem)
    return nfnl_msg(NFT_MSG_NEWSETELEM, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_SET_ELEM_LIST_TABLE, table),
                     nlattr(NFTA_SET_ELEM_LIST_SET, setname),
                     elems])


def seed_newrule_lookup(table='fuzz', chain='input', setname='myset',
                        family=NFPROTO_IPV4):
    """NFT_MSG_NEWRULE — rule with lookup expression referencing a set."""
    NFTA_LOOKUP_SET = 1
    NFTA_LOOKUP_SREG = 2
    expr_lookup = nlattr_nested(NFTA_LIST_ELEM,
                                nlattr(NFTA_EXPR_NAME, 'lookup'),
                                nlattr_nested(NFTA_EXPR_DATA,
                                              nlattr(NFTA_LOOKUP_SET, setname),
                                              nlattr_u32(NFTA_LOOKUP_SREG, 1)))
    exprs = nlattr_nested(NFTA_RULE_EXPRESSIONS, expr_lookup)
    return nfnl_msg(NFT_MSG_NEWRULE, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_RULE_TABLE, table),
                     nlattr(NFTA_RULE_CHAIN, chain),
                     exprs])


def seed_delrule(table='fuzz', chain='input', family=NFPROTO_IPV4):
    """NFT_MSG_DELRULE — delete all rules in a chain."""
    return nfnl_msg(NFT_MSG_DELRULE, family, NLM_F_ACK,
                    [nlattr(NFTA_RULE_TABLE, table),
                     nlattr(NFTA_RULE_CHAIN, chain)])


def seed_newset_map(table='fuzz', name='mymap', family=NFPROTO_IPV4):
    """NFT_MSG_NEWSET — create a map (set with data type)."""
    return nfnl_msg(NFT_MSG_NEWSET, family,
                    NLM_F_CREATE | NLM_F_ACK,
                    [nlattr(NFTA_SET_TABLE, table),
                     nlattr(NFTA_SET_NAME, name),
                     nlattr_u32(NFTA_SET_KEY_TYPE, 7),   # ipv4_addr
                     nlattr_u32(NFTA_SET_KEY_LEN, 4),
                     nlattr_u32(NFTA_SET_DATA_TYPE, 1),  # verdict
                     nlattr_u32(NFTA_SET_DATA_LEN, 4),
                     nlattr_u32(NFTA_SET_FLAGS, NFT_SET_MAP)])


# --- CVE-targeting multi-step batch sequences ---

def seed_batch_full_chain():
    """Full lifecycle: table + base chain + regular chain + rules.
    Exercises chain/rule creation paths deeply."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newchain_regular() +
            seed_newrule_counter() +
            seed_newrule_payload_cmp() +
            seed_newrule_immediate_verdict() +
            batch_end())


def seed_batch_set_with_elements():
    """Table + chain + set + elements + lookup rule.
    Exercises set element insertion and rule-set binding."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newset() +
            seed_newsetelem() +
            seed_newrule_lookup() +
            batch_end())


def seed_batch_anon_set_uaf():
    """CVE-2023-32233 pattern: anonymous set + delete in same batch.
    Anonymous sets are reference-counted; deleting them while bound
    to a rule can trigger use-after-free."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newset_anon() +
            seed_delset(name='__set0') +
            batch_end())


def seed_batch_verdict_chain():
    """CVE-2024-1086 pattern: verdict with NF_DROP + chain deletion.
    Exercises verdict reference counting on chain transitions."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newrule_immediate_verdict(verdict=NF_DROP) +
            seed_newrule_immediate_verdict(verdict=NF_ACCEPT) +
            seed_delrule() +
            seed_delchain() +
            batch_end())


def seed_batch_set_type_confusion():
    """CVE-2022-34918 pattern: set with mismatched key type/length.
    Wrong KEY_LEN for the declared KEY_TYPE can confuse set backends."""
    # Declare ipv4_addr (type=7, should be 4 bytes) but set KEY_LEN=8
    bad_set = nfnl_msg(NFT_MSG_NEWSET, NFPROTO_IPV4,
                       NLM_F_CREATE | NLM_F_ACK,
                       [nlattr(NFTA_SET_TABLE, 'fuzz'),
                        nlattr(NFTA_SET_NAME, 'badset'),
                        nlattr_u32(NFTA_SET_KEY_TYPE, 7),
                        nlattr_u32(NFTA_SET_KEY_LEN, 8),  # wrong!
                        nlattr_u32(NFTA_SET_FLAGS, 0)])
    return (batch_begin() +
            seed_newtable() +
            bad_set +
            batch_end())


def seed_batch_map_operations():
    """Create a verdict map, add elements, and reference from rule.
    Maps have separate data paths from plain sets."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newset_map() +
            seed_newsetelem(setname='mymap') +
            seed_newrule_lookup(setname='mymap') +
            batch_end())


def seed_batch_multi_table():
    """Multiple tables in one batch — exercises concurrent table handling."""
    return (batch_begin() +
            seed_newtable('t1') +
            seed_newtable('t2') +
            seed_newchain_base('t1', 'c1') +
            seed_newchain_base('t2', 'c2') +
            seed_newrule_counter('t1', 'c1') +
            seed_newrule_counter('t2', 'c2') +
            seed_deltable('t1') +
            batch_end())


def seed_batch_create_delete_recreate():
    """Create→delete→recreate: stress object lifetime management.
    Triggers potential dangling pointers if delete/create race."""
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newrule_counter() +
            seed_deltable() +
            seed_newtable() +
            seed_newchain_base() +
            batch_end())


def seed_batch_all_hooks():
    """Base chains for all 5 inet hooks — exercises hook registration."""
    hooks = [
        ('pre', NF_INET_PRE_ROUTING),
        ('in', NF_INET_LOCAL_IN),
        ('fwd', NF_INET_FORWARD),
        ('out', NF_INET_LOCAL_OUT),
        ('post', NF_INET_POST_ROUTING),
    ]
    msgs = batch_begin() + seed_newtable()
    for name, hooknum in hooks:
        msgs += seed_newchain_base(name=name, hooknum=hooknum)
    msgs += batch_end()
    return msgs


def seed_batch_chain_jump():
    """Base chain + regular chain + jump rule.
    Exercises inter-chain verdict handling."""
    # immediate verdict: NFT_JUMP to 'user_chain'
    jump_target = nlattr(1, 'user_chain')  # NFTA_VERDICT_CHAIN
    verdict_data = nlattr_nested(NFTA_DATA_VERDICT,
                                 nlattr_u32(NFTA_VERDICT_CODE, NFT_JUMP),
                                 jump_target)
    expr_jump = nlattr_nested(NFTA_LIST_ELEM,
                              nlattr(NFTA_EXPR_NAME, 'immediate'),
                              nlattr_nested(NFTA_EXPR_DATA,
                                            nlattr_u32(NFTA_IMMEDIATE_DREG, 0),
                                            verdict_data))
    jump_rule = nfnl_msg(NFT_MSG_NEWRULE, NFPROTO_IPV4,
                         NLM_F_CREATE | NLM_F_ACK,
                         [nlattr(NFTA_RULE_TABLE, 'fuzz'),
                          nlattr(NFTA_RULE_CHAIN, 'input'),
                          nlattr_nested(NFTA_RULE_EXPRESSIONS, expr_jump)])
    return (batch_begin() +
            seed_newtable() +
            seed_newchain_base() +
            seed_newchain_regular() +
            jump_rule +
            batch_end())


def pack_batched(*messages):
    """Pack multiple netlink messages into batched harness format.

    Output: [u16 len][msg bytes][u16 len][msg bytes]...
    Each message is prefixed with its length as a little-endian u16.
    """
    out = b''
    for msg in messages:
        out += struct.pack('<H', len(msg)) + msg
    return out


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else 'seeds'
    os.makedirs(outdir, exist_ok=True)

    # Single-message seeds (still useful — one u16 prefix + one msg)
    single_msgs = {
        'newtable': [seed_newtable()],
        'newtable_inet': [seed_newtable('inet_tbl', NFPROTO_INET)],
        'newchain_base': [seed_newchain_base()],
        'newchain_regular': [seed_newchain_regular()],
        'newrule_counter': [seed_newrule_counter()],
        'newrule_payload_cmp': [seed_newrule_payload_cmp()],
        'newrule_verdict_drop': [seed_newrule_immediate_verdict(verdict=NF_DROP)],
        'newset': [seed_newset()],
        'newset_anon': [seed_newset_anon()],
        'newset_map': [seed_newset_map()],
        'newsetelem': [seed_newsetelem()],
        'gettable': [seed_gettable()],
        'deltable': [seed_deltable()],
    }

    # Multi-message batch sequences (the high-value seeds)
    batch_msgs = {
        'batch_create': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newrule_counter(), batch_end(),
        ],
        'batch_create_delete': [
            batch_begin(), seed_newtable(), seed_deltable(), batch_end(),
        ],
        'batch_full_chain': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newchain_regular(), seed_newrule_counter(),
            seed_newrule_payload_cmp(), seed_newrule_immediate_verdict(),
            batch_end(),
        ],
        'batch_set_with_elements': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newset(), seed_newsetelem(), seed_newrule_lookup(),
            batch_end(),
        ],
        'batch_anon_set_uaf': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newset_anon(), seed_delset(name='__set0'), batch_end(),
        ],
        'batch_verdict_chain': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newrule_immediate_verdict(verdict=NF_DROP),
            seed_newrule_immediate_verdict(verdict=NF_ACCEPT),
            seed_delrule(), seed_delchain(), batch_end(),
        ],
        'batch_set_type_confusion': [
            batch_begin(), seed_newtable(),
            nfnl_msg(NFT_MSG_NEWSET, NFPROTO_IPV4,
                     NLM_F_CREATE | NLM_F_ACK,
                     [nlattr(NFTA_SET_TABLE, 'fuzz'),
                      nlattr(NFTA_SET_NAME, 'badset'),
                      nlattr_u32(NFTA_SET_KEY_TYPE, 7),
                      nlattr_u32(NFTA_SET_KEY_LEN, 8),
                      nlattr_u32(NFTA_SET_FLAGS, 0)]),
            batch_end(),
        ],
        'batch_map_operations': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newset_map(), seed_newsetelem(setname='mymap'),
            seed_newrule_lookup(setname='mymap'), batch_end(),
        ],
        'batch_multi_table': [
            batch_begin(), seed_newtable('t1'), seed_newtable('t2'),
            seed_newchain_base('t1', 'c1'), seed_newchain_base('t2', 'c2'),
            seed_newrule_counter('t1', 'c1'), seed_newrule_counter('t2', 'c2'),
            seed_deltable('t1'), batch_end(),
        ],
        'batch_create_delete_recreate': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newrule_counter(), seed_deltable(), seed_newtable(),
            seed_newchain_base(), batch_end(),
        ],
        'batch_all_hooks': [
            batch_begin(), seed_newtable(),
            seed_newchain_base(name='pre', hooknum=NF_INET_PRE_ROUTING),
            seed_newchain_base(name='in', hooknum=NF_INET_LOCAL_IN),
            seed_newchain_base(name='fwd', hooknum=NF_INET_FORWARD),
            seed_newchain_base(name='out', hooknum=NF_INET_LOCAL_OUT),
            seed_newchain_base(name='post', hooknum=NF_INET_POST_ROUTING),
            batch_end(),
        ],
        'batch_chain_jump': [
            batch_begin(), seed_newtable(), seed_newchain_base(),
            seed_newchain_regular(),
            # jump rule built inline
            (lambda: (
                nfnl_msg(NFT_MSG_NEWRULE, NFPROTO_IPV4,
                         NLM_F_CREATE | NLM_F_ACK,
                         [nlattr(NFTA_RULE_TABLE, 'fuzz'),
                          nlattr(NFTA_RULE_CHAIN, 'input'),
                          nlattr_nested(NFTA_RULE_EXPRESSIONS,
                              nlattr_nested(NFTA_LIST_ELEM,
                                  nlattr(NFTA_EXPR_NAME, 'immediate'),
                                  nlattr_nested(NFTA_EXPR_DATA,
                                      nlattr_u32(NFTA_IMMEDIATE_DREG, 0),
                                      nlattr_nested(NFTA_DATA_VERDICT,
                                          nlattr_u32(NFTA_VERDICT_CODE, NFT_JUMP),
                                          nlattr(1, 'user_chain')))))])
            ))(),
            batch_end(),
        ],
    }

    seeds = {}
    for name, msgs in single_msgs.items():
        seeds[name] = pack_batched(*msgs)
    for name, msgs in batch_msgs.items():
        seeds[name] = pack_batched(*msgs)

    for name, data in seeds.items():
        path = os.path.join(outdir, name)
        with open(path, 'wb') as f:
            f.write(data)
        print(f'{path}: {len(data)} bytes')

    print(f'\nGenerated {len(seeds)} seeds in {outdir}/')


if __name__ == '__main__':
    main()
