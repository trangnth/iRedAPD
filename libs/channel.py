import time
import asynchat
import asyncore
import socket

from web import sqlquote

import settings
from libs import SMTP_ACTIONS, TCP_REPLIES, SMTP_SESSION_ATTRIBUTES
from libs import utils, srslib
from libs.logger import logger

if settings.backend == 'ldap':
    from libs.ldaplib.modeler import Modeler
    from libs.ldaplib.conn_utils import is_local_domain

elif settings.backend in ['mysql', 'pgsql']:
    from libs.sql.modeler import Modeler
    from libs.sql import is_local_domain


fqdn = socket.getfqdn()


class DaemonSocket(asyncore.dispatcher):
    """Create socket daemon"""
    def __init__(self, local_addr, db_conns, policy_channel, plugins=None):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(local_addr)
        self.listen(5)
        self.db_conns = db_conns
        self.policy_channel = policy_channel

        self.loaded_plugins = []
        # Get list of LDAP attributes used for account queries
        self.sender_search_attrlist = []
        self.recipient_search_attrlist = []

        # Load enabled plugins.
        if plugins:
            qr = utils.load_enabled_plugins(plugins=plugins)
            self.loaded_plugins = qr['loaded_plugins']
            self.sender_search_attrlist = qr['sender_search_attrlist']
            self.recipient_search_attrlist = qr['recipient_search_attrlist']
            del qr

    def handle_accept(self):
        sock, remote_addr = self.accept()

        if self.policy_channel == 'policy':
            try:
                Policy(sock,
                       db_conns=self.db_conns,
                       plugins=self.loaded_plugins,
                       sender_search_attrlist=self.sender_search_attrlist,
                       recipient_search_attrlist=self.recipient_search_attrlist)
            except Exception as e:
                logger.error("Error while applying policy channel: {}".format(repr(e)))
        elif self.policy_channel == 'srs_sender':
            try:
                SRS(sock, db_conns=self.db_conns, rewrite_address_type='sender')
            except Exception as e:
                logger.error("Error while applying srs (sender): {}".format(repr(e)))

        elif self.policy_channel == 'srs_recipient':
            try:
                SRS(sock, db_conns=self.db_conns, rewrite_address_type='recipient')
            except Exception as e:
                logger.error("Error while applying srs (recipient): {}".format(repr(e)))


class Policy(asynchat.async_chat):
    """Process each smtp policy request"""
    def __init__(self,
                 sock,
                 db_conns=None,
                 plugins=None,
                 sender_search_attrlist=None,
                 recipient_search_attrlist=None):
        asynchat.async_chat.__init__(self, sock)
        self.buffer = []
        self.smtp_session_data = {}
        self.set_terminator(b'\n')

        self.db_conns = db_conns
        self.plugins = plugins
        self.sender_search_attrlist = sender_search_attrlist
        self.recipient_search_attrlist = recipient_search_attrlist

    def push(self, msg):
        try:
            asynchat.async_chat.push(self, (msg + '\n').encode())
        except Exception as e:
            logger.error("Error while pushing message: msg={}, error={}".format(msg, repr(e)))

    def collect_incoming_data(self, data):
        self.buffer.append(data)

    def found_terminator(self):
        if self.buffer:
            # Format received data
            line = self.buffer.pop().decode()

            if '=' in line:
                logger.debug("[policy] {}".format(line))
                (k, v) = line.split('=', 1)

                if k in SMTP_SESSION_ATTRIBUTES:
                    # Convert to lower cases.
                    if k in ['sender', 'recipient', 'sasl_username', 'reverse_client_name']:
                        v = v.lower()
                        self.smtp_session_data[k] = v

                    # Verify email address format
                    if k in ['sender', 'recipient', 'sasl_username']:
                        if v:
                            if not utils.is_email(v):
                                # Don't waste time on invalid email addresses.
                                action = SMTP_ACTIONS['default'] + ' Error: Invalid {} address: {}'.format(k, v)
                                self.push('action=' + action + '\n')

                        self.smtp_session_data[k] = v

                        # Add sender_domain, recipient_domain, sasl_username_domain
                        self.smtp_session_data[k + '_domain'] = v.split('@', 1)[-1]

                        if k in ['sender', 'recipient']:
                            # Add sender_without_ext, recipient_without_ext
                            self.smtp_session_data[k + '_without_ext'] = utils.strip_mail_ext_address(v)
                    else:
                        self.smtp_session_data[k] = v
                else:
                    logger.debug("[policy] Drop invalid smtp session input: {}".format(line))

        elif self.smtp_session_data:
            # Track how long a request takes
            _start_time = time.time()

            # Gather data at RCPT , data will be used at END-OF-MESSAGE
            _protocol_state = self.smtp_session_data['protocol_state']

            # Call modeler and apply plugins
            try:
                modeler = Modeler(conns=self.db_conns)
                result = modeler.handle_data(
                    smtp_session_data=self.smtp_session_data,
                    plugins=self.plugins,
                    sender_search_attrlist=self.sender_search_attrlist,
                    recipient_search_attrlist=self.recipient_search_attrlist,
                )

                if result:
                    action = result
                else:
                    action = SMTP_ACTIONS['default']
                    logger.error("No result returned by modeler, fallback to default action: {}.".format(action))

            except Exception as e:
                action = SMTP_ACTIONS['default']
                logger.error("Unexpected error: {}. Fallback to default action: {}".format(repr(e), action))

            self.push('action=' + action + '\n')
            logger.debug("Session ended.")

            _end_time = time.time()
            utils.log_policy_request(smtp_session_data=self.smtp_session_data,
                                     action=action,
                                     start_time=_start_time,
                                     end_time=_end_time)

            # Log smtp session.
            # Postfix may send the smtp session data twice or even more if
            # iRedAPD is called in multiple protocol states, try to avoid
            # "duplicate" logging here.
            if _protocol_state == 'END-OF-MESSAGE' or \
               (_protocol_state == 'RCPT' and not action.startswith('DUNNO')):
                utils.log_smtp_session(conn=self.db_conns['conn_iredapd'],
                                       smtp_action=action,
                                       **self.smtp_session_data)
        else:
            action = SMTP_ACTIONS['default']
            logger.debug("replying: {}".format(action))
            self.push('action=' + action + '\n')
            logger.debug("Session ended")


class SRS(asynchat.async_chat):
    """Process request from Postfix tcp table."""
    def __init__(self,
                 sock,
                 db_conns=None,
                 rewrite_address_type='sender'):
        asynchat.async_chat.__init__(self, sock)
        self.buffer = []
        self.set_terminator(b'\n')
        self.db_conns = db_conns
        self.log_prefix = '[srs][' + rewrite_address_type + '] '
        self.rewrite_address_type = rewrite_address_type
        self.srslib_instance = srslib.SRS(secret=settings.srs_secrets[0],
                                          prev_secrets=settings.srs_secrets[1:])

    def push(self, msg):
        try:
            asynchat.async_chat.push(self, (msg + '\n').encode())
        except Exception as e:
            logger.error("Error while pushing message: error={}, message={}".format(repr(e), msg))

    def collect_incoming_data(self, data):
        self.buffer.append(data)

    def srs_forward(self, addr, domain):
        # if domain is hostname, virtual mail domain or srs_domain, do not rewrite.
        if domain == settings.srs_domain:
            reply = TCP_REPLIES['not_exist'] + 'Domain is srs_domain, bypassed.'
            return reply
        elif domain == fqdn:
            reply = TCP_REPLIES['not_exist'] + 'Domain is server hostname, bypassed.'
            return reply
        else:
            _is_local_domain = False
            try:
                conn_vmail = self.db_conns['conn_vmail']
                _is_local_domain = is_local_domain(conn=conn_vmail, domain=domain)
            except Exception as e:
                logger.error("{} Error while verifying domain: {}".format(self.log_prefix, repr(e)))

            if _is_local_domain:
                reply = TCP_REPLIES['not_exist'] + 'Domain is a local mail domain, bypassed.'
                return reply
            else:
                possible_domains = []
                _splited_parts = domain.split('.')
                _length = len(_splited_parts)
                for i in range(_length):
                    _part1 = '.'.join(_splited_parts[-i:])
                    _part2 = '.' + _part1
                    possible_domains += [_part1, _part2]

                conn_iredapd = self.db_conns['conn_iredapd']
                sql = """SELECT id FROM srs_exclude_domains WHERE domain IN %s LIMIT 1""" % sqlquote(list(possible_domains))
                logger.debug("{} [SQL] Query srs_exclude_domains: {}".format(self.log_prefix, sql))

                #try:
                #    qr = conn_iredapd.execute(sql)
                #    sql_record = qr.fetchone()
                #    logger.debug("{} [SQL] Query result: {}".format(self.log_prefix, sql_record))
                #except Exception as e:
                #    logger.debug("{} Error while querying SQL: {}".format(self.log_prefix, repr(e)))
                #    reply = TCP_REPLIES['not_exist']
                #    return reply

                sql_record = 0
                if sql_record:
                    reply = TCP_REPLIES['not_exist'] + 'Domain is explicitly excluded, bypassed.'
                    return reply
                else:
                    try:
                        new_addr = str(self.srslib_instance.forward(addr, settings.srs_domain))
                        logger.info("{} rewrote: {} -> {}".format(self.log_prefix, addr, new_addr))
                        reply = TCP_REPLIES['success'] + new_addr
                        return reply
                    except Exception as e:
                        logger.debug("{} Error while generating forward address: {}".format(self.log_prefix, repr(e)))
                        # Return original address.
                        reply = TCP_REPLIES['not_exist']
                        return reply

    def srs_reverse(self, addr):
        # if address is not srs address, do not reverse.
        _is_srs_address = self.srslib_instance.is_srs_address(addr, strict=True)

        if _is_srs_address:
            # Reverse
            try:
                new_addr = str(self.srslib_instance.reverse(addr))
                logger.info("{} reversed: {} -> {}".format(self.log_prefix, addr, new_addr))
                reply = TCP_REPLIES['success'] + new_addr
            except Exception as e:
                logger.debug("{} Error while generating reverse address: {}".format(self.log_prefix, repr(e)))

                # Return original address.
                reply = TCP_REPLIES['not_exist']
        else:
            reply = TCP_REPLIES['not_exist'] + 'Not a valid SRS address, bypassed.'

        return reply

    def found_terminator(self):
        if self.buffer:
            line = self.buffer.pop().decode()
            logger.debug("{} input: {}".format(self.log_prefix, line))

            if line.startswith('get '):
                addr = line.strip().split(' ', 1)[-1]

                if utils.is_email(addr):
                    domain = addr.split('@', 1)[-1]

                    if self.rewrite_address_type == 'sender':
                        reply = self.srs_forward(addr=addr, domain=domain)
                        logger.debug("{} {}".format(self.log_prefix, reply))
                        self.push(reply)
                    else:
                        reply = self.srs_reverse(addr=addr)
                        logger.debug("{} {}".format(self.log_prefix, reply))
                        self.push(reply)
                else:
                    logger.debug("{} Not a valid email address, bypassed.".format(self.log_prefix))
                    self.push(TCP_REPLIES['not_exist'] + 'Not a valid email address, bypassed.')
            else:
                logger.debug("{} Unexpected input: {}".format(self.log_prefix, line))
                self.push(TCP_REPLIES['not_exist'] + 'Unexpected input: {}'.format(line))
