# Author: TrangUET <github.com/trangnth>
#
# Purpose: Reject senders listed in per-user blacklists, bypass senders listed
#          in per-user whitelists stored in Amavisd database (@lookup_sql_dsn).
#
# Note: Amavisd is configured to be an after-queue content filter in iRedMail.
#       with '@lookup_sql_dsn' setting enabled in Amavisd config file, Amavisd
#       will query per-recipient, per-domain and server-wide (a.k.a. catch-all)
#       white/blacklists and policy rules (tables: `mailaddr`, `users`,
#       `wblist`, `policy`) stored in Amavisd SQL database.
#
#       if you don't enable this plugin, Amavisd will quarantine emails sent
#       from blacklisted senders, and bypass spam scanning for emails sent from
#       whitelisted senders (note: other checkings like banned filename, bad
#       headers, virus are still checked - if you didn't disable them in
#       `amavisd.policy`). With this plugin, we can tell Postfix to reject
#       blacklisted sender BEFORE email enter mail queue, or bypass emails sent
#       from whitelisted senders directly.
#
# How to use this plugin:
#
#   *) Enable `@lookup_sql_dsn` with correct SQL account credential in Amavisd
#      config file.
#
#   *) Set Amavisd lookup SQL database related parameters (`amavisd_db_*`) in
#      iRedAPD config file `/opt/iredapd/settings.py`.
#
#   *) Enable this plugin in iRedAPD config file `/opt/iredapd/settings.py`,
#      parameter `plugins =`.
#
#   *) Restart iRedAPD service.
#
# Formats of valid white/blacklist senders:
#
#   - user@domain.com:  single sender email address
#   - @domain.com:  entire sender domain
#   - @.domain.com: entire sender domain and all sub-domains
#   - @.:           all senders
#   - 192.168.1.2: single sender ip address
#   - 192.168.1.0/24: CIDR network.
#   - 192.168.1.*, 192.168.*.2: wildcard sender ip addresses. [DEPRECATED]
#                   NOTE: if you want to use wildcard IP address like
#                   '192.*.1.2', '192.*.*.2', please set
#                   'WBLIST_ENABLE_ALL_WILDCARD_IP = True' in
#                   /opt/iredapd/settings.py.

import ipaddress
from web import sqlquote
from libs.logger import logger
from libs import SMTP_ACTIONS, utils
import settings

SMTP_PROTOCOL_STATE = ["RCPT"]
REQUIRE_AMAVISD_DB = True

if settings.backend == "ldap":
    from libs.ldaplib.conn_utils import is_local_domain, get_alias_target_domain
else:
    from libs.sql import is_local_domain, get_alias_target_domain


if settings.WBLIST_DISCARD_INSTEAD_OF_REJECT:
    reject_action = SMTP_ACTIONS["discard"]
else:
    reject_action = SMTP_ACTIONS["reject_blacklisted"]


def get_id_of_possible_cidr_network(conn, client_address):
    """Return list of `mailaddr.id` which are CIDR network addresses."""
    ids = []

    if not client_address:
        logger.debug("No client address.")
        return ids

    try:
        _ip = ipaddress.ip_address(client_address)
        if _ip.version == 4:
            first_field = client_address.split(".")[0]
            sql_cidr = first_field + r".%%"
        else:
            return ids
    except:
        return ids

    sql = """SELECT id, email
               FROM mailaddr
              WHERE email LIKE %s
           ORDER BY priority DESC""" % sqlquote(sql_cidr)
    logger.debug("[SQL] Query CIDR network: \n{}".format(" ".join(sql.replace('\n', ' ').split())))

    try:
        qr = conn.execute(sql)
        qr_cidr = qr.fetchall()
    except Exception as e:
        logger.error("Error while querying CIDR network: {}, SQL: \n{}".format(repr(e), sql))
        return ids

    if qr_cidr:
        _cidrs = [(int(r.id), utils.bytes2str(r.email)) for r in qr_cidr]

        # Get valid CIDR.
        _ip_networks = set()
        for (_id, _cidr) in _cidrs:
            # Verify whether client_address is in CIDR network
            try:
                _net = ipaddress.ip_network(_cidr)
                _ip_networks.add((_id, _net))
            except:
                pass

        if _ip_networks:
            _ip = ipaddress.ip_address(client_address)
            for (_id, _net) in _ip_networks:
                if _ip in _net:
                    ids.append(_id)

    logger.debug("IDs of CIDR network(s): {}".format(ids))
    return ids


def get_id_of_external_addresses(conn, addresses):
    """Return list of `mailaddr.id` of external addresses."""
    ids = []

    if not addresses:
        logger.debug("No addresses, return empty list of ids.")
        return ids

    # Get `mailaddr.id` of external addresses, ordered by priority
    sql = """SELECT id, email
               FROM mailaddr
              WHERE email IN %s
           ORDER BY priority DESC""" % sqlquote(addresses)
    logger.debug("[SQL] Query external addresses: \n{}".format(" ".join(sql.replace('\n', ' ').split())))

    try:
        qr = conn.execute(sql)
        qr_addresses = qr.fetchall()
    except Exception as e:
        logger.error("Error while getting list of id of external addresses: {}, SQL: {}".format(repr(e), sql))
        return ids

    if qr_addresses:
        ids = [int(r.id) for r in qr_addresses]

    if not ids:
        # don't waste time if we don't even have senders stored in sql db.
        logger.debug("No record found in SQL database.")
        return []
    else:
        logger.debug("Addresses (in `mailaddr`): {}".format(qr_addresses))
        return ids


def get_id_of_local_addresses(conn, addresses):
    """Return list of `users.id` of local addresses."""

    # Get `users.id` of local addresses
    sql = """SELECT id, email
               FROM users
              WHERE email IN %s AND type='WB'
           ORDER BY priority DESC""" % sqlquote(addresses)
    logger.debug("[SQL] Query local addresses: \n{}".format(" ".join(sql.replace('\n', ' ').split())))

    ids = []
    try:
        qr = conn.execute(sql)
        qr_addresses = qr.fetchall()
        if qr_addresses:
            ids = [int(r.id) for r in qr_addresses]
            logger.debug("Local addresses (in `users` table): {}".format(qr_addresses))
    except Exception as e:
        logger.error("Error while executing SQL command: {}".format(repr(e)))

    if not ids:
        # don't waste time if we don't have any per-recipient wblist.
        logger.debug("No record found in SQL database.")
        return []
    else:
        return ids


def apply_inbound_wblist(conn, sender_ids, recipient_ids):
    # Return if no valid sender or recipient id.
    if not (sender_ids and recipient_ids):
        logger.debug("No valid sender id or recipient id.")
        return SMTP_ACTIONS["default"]

#    # Get wblist_group
#    #logger.debug("TRRRRRANG - %s" % sqlquote(recipient_ids))
#    sql = """SELECT mailgroup_id,sender_id
#                FROM wblist_mailgroup
#                WHERE mailgroup_id IN %s""" % (sqlquote(recipient_ids))
#    logger.debug("[SQL] Query inbound wblist_group (in `wblist_group`): {}" . format(" ".join(sql.replace('\n', ' ').split())))
#
#    qr = conn.execute(sql)
#    wblists_group = qr.fetchall()
#
#    logger.debug("TRANG_DEBUG: {}" . format(wblists_group))
#    if not wblists_group:
#        # no wblists_group
#        logger.debug("No wblist for group found.")
#        #return SMTP_ACTIONS["default"]
#    else:
#        logger.debug("Found inbound wblist_group (default reject all sender send email to group): {}".format(wblists_group))
#    
#        # Check sender addresses
#        for rid in recipient_ids:
#            for sid in sender_ids:
#                logger.debug("TRANG_DEBUG {}-{}, wblists_group: {}".format(rid,sid, wblists_group))
#                if (rid, sid) in wblists_group:
#                    logger.info("Whitelisted to group: wblist_group=({}, {})".format(rid, sid))
#                    return SMTP_ACTIONS["default"]
#
#        logger.info("Blacklisted to group: wblist_group={}".format(rid))
#        return SMTP_ACTIONS["reject_blacklisted_group"]

    # Get wblist_group
    #logger.debug("TRRRRRANG - %s" % sqlquote(recipient_ids))
    sql = """SELECT rid, sid, wb
                FROM wblist
                WHERE rid IN %s
                AND type='maillist'""" % (sqlquote(recipient_ids))
    logger.debug("[SQL] Query inbound wblist_group (in `wblist_group`): {}" . format(" ".join(sql.replace('\n', ' ').split())))

    qr = conn.execute(sql)
    wblists_group = qr.fetchall()

    logger.debug("TRANG_DEBUG: wblist_group: {}" . format(wblists_group))
    if not wblists_group:
        # no wblists_group
        logger.debug("No wblist for group found.")
        #return SMTP_ACTIONS["default"]
    else:
        sql = """SELECT rid, sid
                    FROM wblist
                    WHERE rid IN %s
                    AND type='maillist'
                    AND wb='W'""" % (sqlquote(recipient_ids))
        logger.debug("[SQL] Query inbound wblist for group (in `wblist`): {}" . format(" ".join(sql.replace('\n', ' ').split())))
        qr = conn.execute(sql)
        wblists = qr.fetchall()

        if not wblists:
            # no user for whitelist
            logger.debug("No whitelist sender for group found.")
        else:
            logger.debug("Found inbound wblist_group (default reject all sender send email to group): {}".format(wblists))
    
            # Check sender addresses
            for rid in recipient_ids:
                for sid in sender_ids:
                    logger.debug("TRANG_DEBUG {}-{}, wblists_group: {}".format(rid,sid, wblists))
                    if (rid, sid) in wblists:
                        logger.info("Whitelisted to group: wblist_group=({}, {})".format(rid, sid))
                        return SMTP_ACTIONS["default"]

        logger.info("Blacklisted to group: wblist_group={}".format(wblists_group))
        return SMTP_ACTIONS["reject_blacklisted_group"]


    # Get wblist
    sql = """SELECT rid, sid, wb
               FROM wblist
              WHERE sid IN %s
                AND rid IN %s
                ORDER BY priority DESC""" % (sqlquote(sender_ids), sqlquote(recipient_ids))
    logger.debug("[SQL] Query inbound wblist (in `wblist`): {}".format(" ".join(sql.replace('\n', ' ').split())))
    qr = conn.execute(sql)
    wblists = qr.fetchall()

    if not wblists:
        # no wblist
        logger.debug("No wblist found.")
        return SMTP_ACTIONS["default"]

    logger.debug("Found inbound wblist: {}".format(wblists))

    # Check sender addresses
    # rids/recipients are orded by priority
    
    logger.debug("recipient_ids: %s" %recipient_ids)
    logger.debug("sender_ids: %s" % sender_ids)
#    for rid in recipient_ids:
#        # sids/senders are sorted by priority
#        for sid in sender_ids:
#            logger.debug("%s %s W", rid, sid)
#            if (rid, sid, "W") in wblists:
#                logger.info("Whitelisted: wblist=({}, {}, 'W')".format(rid, sid))
#                return SMTP_ACTIONS["whitelist"]
#
#            if (rid, sid, "B") in wblists:
#                logger.info("Blacklisted: wblist=({}, {}, 'B')".format(rid, sid))
#                return reject_action

    for wb in wblists:
        for rid in recipient_ids:
            # sids/senders are sorted by priority
            for sid in sender_ids:
                logger.debug("%s - %s %s W", wb, rid, sid)
                if (rid, sid, "W") ==  wb:
                    logger.info("Whitelisted: wblist=({}, {}, 'W')".format(rid, sid))
                    return SMTP_ACTIONS["default"]
    
                if (rid, sid, "B") == wb:
                    logger.info("Blacklisted: wblist=({}, {}, 'B')".format(rid, sid))
                    return reject_action


    return SMTP_ACTIONS["default"]


def apply_outbound_wblist(conn, sender_ids, recipient_ids):
    # Return if no valid sender or recipient id.
    if not (sender_ids and recipient_ids):
        logger.debug("No valid sender id or recipient id.")
        return SMTP_ACTIONS["default"]

    # Bypass outgoing emails.
    if settings.WBLIST_BYPASS_OUTGOING_EMAIL:
        logger.debug("Bypass outgoing email as defined in WBLIST_BYPASS_OUTGOING_EMAIL.")
        return SMTP_ACTIONS["default"]

    # Get wblist
    sql = """SELECT rid, sid, wb
               FROM outbound_wblist
              WHERE sid IN %s
                AND rid IN %s""" % (sqlquote(sender_ids), sqlquote(recipient_ids))
    logger.debug("[SQL] Query outbound wblist: \n{}".format(" ".join(sql.replace('\n', ' ').split())))
    qr = conn.execute(sql)
    wblists = qr.fetchall()

    if not wblists:
        # no wblist
        logger.debug("No wblist found.")
        return SMTP_ACTIONS["default"]

    logger.debug("Found outbound wblist: {}".format(wblists))

    # Check sender addresses
    # rids/recipients are orded by priority
    for sid in sender_ids:
        for rid in recipient_ids:
            if (rid, sid, "W") in wblists:
                logger.info("Whitelisted: outbound_wblist=({}, {}, 'W')".format(rid, sid))
                return SMTP_ACTIONS["default"] + " outbound_wblist=({}, {}, 'W')".format(rid, sid)

            if (rid, sid, "B") in wblists:
                logger.info("Blacklisted: outbound_wblist=({}, {}, 'B')".format(rid, sid))
                return reject_action

    return SMTP_ACTIONS["default"]


def restriction(**kwargs):
    logger.info("Trangnth - mailgroup level restriction")
    conn = kwargs["conn_amavisd"]
    conn_vmail = kwargs["conn_vmail"]

    if not conn:
        logger.error("Error, no valid Amavisd database connection.")
        return SMTP_ACTIONS["default"]

    # Get sender and recipient
    sender = kwargs["sender_without_ext"]
    sender_domain = kwargs["sender_domain"]
    recipient = kwargs["recipient_without_ext"]
    recipient_domain = kwargs["recipient_domain"]

    smtp_session_data = kwargs['smtp_session_data']
    protocol_state = smtp_session_data['protocol_state']

    if kwargs["sasl_username"]:
        # Use sasl_username as sender for outgoing email
        sender = kwargs["sasl_username"]
        sender_domain = kwargs["sasl_username_domain"]

    if not sender:
        logger.debug("SKIP: no sender address.")
        return SMTP_ACTIONS["default"]

    if sender == recipient:
        logger.debug("SKIP: Sender is same as recipient.")
        return SMTP_ACTIONS["default"]

    sql = """SELECT level
                FROM maillist
              WHERE mailgroup = %s
                AND active = 1
             LIMIT 1""" % sqlquote(recipient)
    try:
        qr = conn.execute(sql)
        qr_level = qr.fetchall()
    except Exception as e:
        logger.error("Error while querying level for maillist: {}, SQL: \n{}".format(repr(e), " ".join(sql.replace('\n', ' ').split())))
    
    # If recipient is email group
    if qr_level:
        level = [int(r.level) for r in qr_level]
        logger.debug("TRANGNTH_DEBUG: %s" % level)
        if 1 in level:
            # Allow all sender send email to group
            logger.debug("Allow all sender send email to group")
            return SMTP_ACTIONS["default"]
        elif 2 in level and sender_domain == recipient_domain:
            # Allow if sender has same domain 
            return SMTP_ACTIONS["default"]
            logger.debug("Allow if sender has same domain")    
        elif 3 in level:
            # Allow group member send email to group
            sql = """SELECT dest_mail_address
                        FROM maillist
                        WHERE mailgroup = %s""" % sqlquote(recipient)
            try:
                qr = conn.execute(sql)
                qr_dest_mails = qr.fetchall()
                qr_dest_mails = [ i[0] for i in qr_dest_mails if i[0] != "" ]
            except Exception as e:
                logger.error("Error while querying dest_mail_address for maillist: {}, SQL: \n{}".format(repr(e), " ".join(sql.replace('\n', ' ').split())))
            logger.info("level 3 %s" % qr_dest_mails)

            if qr_dest_mails and sender in qr_dest_mails:
                logger.debug("Allow group member send email to group")
                return SMTP_ACTIONS["default"]
        elif 4 in level:
            # Only allow some sender sen mail to group 
            

            
            # Get `users.id` of local addresses
            valid_recipients = utils.get_policy_addresses_from_email(mail=recipient)
            sql = """SELECT id, email                                                                          
                       FROM users                                                                              
                      WHERE email IN %s AND type='WB'                                                          
                   ORDER BY priority DESC""" % sqlquote(valid_recipients)                                         
            logger.debug("[SQL] Query local addresses: \n{}".format(" ".join(sql.replace('\n', ' ').split()))) 
                                                                                                               
            recipient_ids = []
            try:                                                                                               
                qr = conn.execute(sql)                                                                         
                qr_addresses = qr.fetchall()                                                                   
                if qr_addresses:                                                                               
                    recipient_ids = [int(r.id) for r in qr_addresses]
                    logger.debug("Local addresses (in `users` table): {}".format(qr_addresses))                
            except Exception as e:                                                                             
                logger.error("Error while executing SQL command: {}".format(repr(e)))

            if not recipient_ids:
                # don't waste time if we don't have any per-recipient wblist.                                  
                logger.debug("No record found in SQL database.")                                               


            sender_ids = []
            valid_senders = utils.get_policy_addresses_from_email(mail=sender)
#            if not valid_senders:                                         
#                logger.debug("No addresses, return empty list of ids.")     
                                                                                              
            # Get `mailaddr.id` of external addresses, ordered by priority                                      
            sql = """SELECT id, email                   
                       FROM mailaddr                                         
                      WHERE email IN %s                                                                  
                   ORDER BY priority DESC""" % sqlquote(valid_senders)
            logger.debug("[SQL] Query external addresses: \n{}".format(" ".join(sql.replace('\n', ' ').split())))  
                                                                                                   
            try:                                                                     
                qr = conn.execute(sql)                                                                            
                qr_addresses = qr.fetchall()                                                                      
            except Exception as e:                                                                           
                logger.error("Error while getting list of id of external addresses: {}, SQL: {}".format(repr(e), sql))
                                                                                                                  
            if qr_addresses:                                                                                     
                sender_ids = [int(r.id) for r in qr_addresses]
                                                                               
            if not sender_ids: 
                # don't waste time if we don't even have senders stored in sql db.                               
                logger.debug("No record found in SQL database.")                                                  
            else:                                                                                                
                logger.debug("Addresses (in `mailaddr`): {}".format(qr_addresses))                              









            sql = """SELECT rid, sid
                        FROM wblist 
                        WHERE rid IN %s 
                        AND type='maillist' 
                        AND wb='W'""" % (sqlquote(recipient_ids))                                                          
            logger.debug("[SQL] Query inbound wblist for group (in `wblist`): {}" . format(" ".join(sql.replace('\n', ' ').split())))                               
            qr = conn.execute(sql)                                  
            wblists = qr.fetchall() 
                                                                                                                           
            if not wblists:         
                # no user for whitelist                                                             
                logger.debug("No whitelist sender for group found.")
            else:                                                   
                logger.debug("Found inbound wblist_group (default reject all sender send email to group): {}. Checking...".format(wblists))
                                                                
                # Check sender addresses            
                for rid in recipient_ids:                                                                       
                    for sid in sender_ids:                                                              
                        logger.debug("TRANG_DEBUG {}-{}, wblists_group: {}".format(rid,sid, wblists))           
                        if (rid, sid) in wblists:                                                           
                            logger.info("Whitelisted to group: wblist_group=({}, {})".format(rid, sid))     
                            return SMTP_ACTIONS["default"]                  
                                                                                                                           
            logger.info("Blacklisted to group: wblist_group={}".format(wblists))  
            return SMTP_ACTIONS["reject_blacklisted_group"]     

        #else:
        return SMTP_ACTIONS["reject_blacklisted_group"]




#    valid_senders = utils.get_policy_addresses_from_email(mail=sender)
#    valid_recipients = utils.get_policy_addresses_from_email(mail=recipient)
#
#    if not kwargs["sasl_username"]:
#        # Sender `username@*`
#        sender_username = sender.split("@", 1)[0]
#        if "+" in sender_username:
#            valid_senders.append(sender_username.split("+", 1)[0] + "@*")
#        else:
#            valid_senders.append(sender_username + "@*")
#
#    # Append original IP address
#    client_address = kwargs["client_address"]
#    valid_senders.append(client_address)
#
#    # Append all possible wildcast IP addresses
#    if utils.is_ipv4(client_address):
#        valid_senders += utils.wildcard_ipv4(client_address)
#
#    alias_target_sender_domain = get_alias_target_domain(alias_domain=sender_domain, conn=conn_vmail)
#    if alias_target_sender_domain:
#        _mail = sender.split("@", 1)[0] + "@" + alias_target_sender_domain
#        valid_senders += utils.get_policy_addresses_from_email(mail=_mail)
#
#    alias_target_rcpt_domain = get_alias_target_domain(alias_domain=recipient_domain, conn=conn_vmail)
#    logger.debug("TRANGDEBUG-recipient_domain: %s" % recipient_domain)
#
#    if alias_target_rcpt_domain:
#        _mail = recipient.split("@", 1)[0] + "@" + alias_target_rcpt_domain
#        valid_recipients += utils.get_policy_addresses_from_email(mail=_mail)
#
#    logger.debug("Possible policy senders: {}".format(valid_senders))
#    logger.debug("Possible policy recipients: {}".format(valid_recipients))
#
#    id_of_client_cidr_networks = []
#    client_cidr_network_checked = False
#
#    # Outbound
#    if kwargs["sasl_username"]:
#        logger.debug("Apply wblist for outbound message.")
#
#        id_of_local_addresses = get_id_of_local_addresses(conn, valid_senders)
#
#        id_of_ext_addresses = []
#        if id_of_local_addresses:
#            id_of_ext_addresses = get_id_of_external_addresses(conn, valid_recipients)
#
#            id_of_client_cidr_networks = get_id_of_possible_cidr_network(conn, client_address)
#            client_cidr_network_checked = True
#
#        action = apply_outbound_wblist(conn,
#                                       sender_ids=id_of_local_addresses + id_of_client_cidr_networks,
#                                       recipient_ids=id_of_ext_addresses)
#
#        if not action.startswith("DUNNO"):
#            return action

#    check_inbound = False
#    if not kwargs["sasl_username"]:
#        check_inbound = True
#
#    if (not check_inbound) and kwargs["sasl_username"] and (sender_domain == recipient_domain):
#        # Local user sends to another user in same domain
#        check_inbound = True
#
#    if not check_inbound:
#        rcpt_domain_is_local = is_local_domain(conn=conn_vmail, domain=recipient_domain, include_alias_domain=False)
#        if alias_target_rcpt_domain or rcpt_domain_is_local:
#            # Local user sends to another local user in different domain
#            check_inbound = True
#
#    if check_inbound:
#        logger.debug("Apply mailgroup_level for inbound message.")
#
#        id_of_ext_addresses = []
#        id_of_local_addresses = get_id_of_local_addresses(conn, valid_recipients)
#        if id_of_local_addresses:
#            id_of_ext_addresses = get_id_of_external_addresses(conn, valid_senders)
#
#            if not client_cidr_network_checked:
#                id_of_client_cidr_networks = get_id_of_possible_cidr_network(conn, client_address)
#
#        action = apply_inbound_maillist_level(conn,
#                                      sender_ids=id_of_ext_addresses + id_of_client_cidr_networks,
#                                      recipient_ids=id_of_local_addresses)
#
#        if not action.startswith("DUNNO"):
#            return action

    return SMTP_ACTIONS["default"]
