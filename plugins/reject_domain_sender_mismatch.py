# Author: Trang Nguyen <trangnth@bizflycloud.vn>
#
# Purpose: Sender login can not same sender in 'Return-Path:' header
#          Each sender login will be allow some domain sent then relay to next host
#          Reject any message has domain in 'Return-Path:' header  not be list that allowed by sender 
# 
# Example sender (Return-Path: in header) not same sasl_username (sender login):
# user login: trangnth17@toandungmedia.vn
# sender_email: trangnth14@toandungmedia.vn  -> "server.sendmail("trangnth14@toandungmedia.vn", receiver_email, message.as_string())""
#     [policy] request=smtpd_access_policy
#     [policy] protocol_state=END-OF-MESSAGE
#     [policy] protocol_name=ESMTP
#     [policy] client_address=113.160.0.10
#     [policy] client_name=unknown
#     [policy] client_port=51350
#     [policy] reverse_client_name=static.vnpt-hanoi.com.vn
#     [policy] server_address=x.x.x.x
#     [policy] server_port=587
#     [policy] helo_name=[127.0.1.1]
#     [policy] sender=trangnth14@toandungmedia.vn
#     [policy] recipient=trangnth2@bizflycloud.vn
#     [policy] recipient_count=1
#     [policy] queue_id=0D8CE3F38F
#     [policy] sasl_method=PLAIN
#     [policy] sasl_username=trangnth17@toandungmedia.vn
#     [policy] sasl_sender=
#     [policy] encryption_protocol=TLSv1.3
#     [policy] encryption_cipher=TLS_AES_256_GCM_SHA384
#     [policy] encryption_keysize=256
#     Skip plugin: reject_null_sender (protocol_state != END-OF-MESSAGE)
#     Session ended.
#     [113.160.0.10] END-OF-MESSAGE, trangnth17@toandungmedia.vn => trangnth14@toandungmedia.vn -> trangnth2@bizflycloud.vn, DUNNO [recipient_count=1, size=787, process_time=0.0339s]
#
# How to use this plugin:
#
# *) Enable this plugin in iRedAPD config file /opt/iredapd/settings.py:
#
#    plugins = ['reject_domain_sender_mismatch', ...]
#
# *) Restart iRedAPD service.

from libs.logger import logger
from libs import SMTP_ACTIONS
from web import sqlquote

SMTP_PROTOCOL_STATE = ['RCPT']

def restriction(**kwargs):
    conn = kwargs['conn_iredapd']
    sender = kwargs['sender']
    sasl_username = kwargs['sasl_username']
    domain_sender = sender.split('@')[1]

    # Query domain 
    sql_1 = "select domain from domain_mkt where address='%s' and domain='%s'" % (sasl_username, domain_sender)
    # Query subdomain
    sql_2 = "select domain from domain_mkt where address={} and domain like {}" . format(sqlquote(sasl_username), sqlquote("%%*%%"))

    logger.debug('[SQL] Query domain sender : {}'.format(sql_1))
    query = conn.execute(sql_1)
    domains = query.fetchall()

    logger.debug('[SQL] Query domain result: {}'.format(domains))

    if not domains:
        query_2 = conn.execute(sql_2)
        logger.debug('[SQL] Query subdomain sender: {}' .format(sql_2))
        domains_2 = query_2.fetchall()
        logger.debug('[SQL] Query subdomain result: {}'.format(domains_2))
        if domains_2:
            for d in domains_2:
                logger.info(d)
                if d[0].replace("*", "") in domain_sender:
                    logger.info("subdomain ok")
                    return SMTP_ACTIONS['default']

            logger.info("subdomain not ok")
            return SMTP_ACTIONS['default']
        else:
            logger.info("subdomain not found")
            return SMTP_ACTIONS['default']

    else:
        logger.info("domain ok")
        return SMTP_ACTIONS['default']

#    logger.info("domain and subdomain not ok")
#    return SMTP_ACTIONS['default']
