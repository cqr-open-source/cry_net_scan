import json
import sys

try:
    from impacket.smbconnection import SMBConnection
    from impacket.nmb import NetBIOS
    from impacket.dcerpc.v5.samr import *
    from impacket.dcerpc.v5.lsad import *
    from impacket.dcerpc.v5.wkst import *
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5
    from impacket.dcerpc.v5 import transport, samr, lsad, wkst

except ImportError:
    # If impacket is not found, print a JSON error message to stdout and exit.
    print(json.dumps({
        "target_ip": "N/A",
        "status": "error",
        "error_message": "Impacket library not found. Please install it using: pip install impacket"
    }, indent=4, ensure_ascii=False))
    sys.exit(1)

class Enum4LinuxNGScanner:
    """
    Class for performing specialized SMB/NetBIOS enumeration using pure Python libraries (Impacket).
    Designed for integration into a larger scanning system, providing cross-OS compatibility.
    """

    def __init__(self, target_ip):
        """
        Initializes the scanner for the specified target IP address.
        :param target_ip: The IP address of the target host.
        """
        self.target_ip = target_ip
        self.results = {
            "target_ip": target_ip,
            "status": "success",
            "findings": {}
        }
        self.smb_con = None
        self.dce_samr = None
        self.dce_lsad = None
        self.dce_wkst = None

    def _add_finding(self, description, data, success=True, error=None):
        """Helper to add findings to the results dictionary."""
        self.results["findings"][description] = {
            "data": data,
            "success": success,
            "error": error
        }

    def _connect_smb(self):
        """Establishes an SMB connection to the target."""
        try:
            # Try different SMB dialects for broader compatibility
            # SMB v2/3 dialects are preferred.
            # dialects = [SMB_DIALECT_SMB3_11, SMB_DIALECT_SMB3_02, SMB_DIALECT_SMB3_00, SMB_DIALECT_SMB2_10,
            #             SMB_DIALECT_SMB2_02]
            dialects = ['SMB3_11', 'SMB3_02', 'SMB3_00', 'SMB2_10', 'SMB2_02', 'NT LM 0.12'] # Added NT LM 0.12 for older servers


            # The port is typically 445 for SMB
            smb_port = 445

            for dialect in dialects:
                try:
                    # Attempt connection with a specific dialect
                    self.smb_con = SMBConnection(self.target_ip, self.target_ip, sess_port=smb_port,
                                                 preferredDialect=dialect)
                    # Attempt anonymous/null session login
                    self.smb_con.login('', '')
                    self._add_finding("smb_connection",
                                      {"message": f"SMB connection established with dialect {dialect}"}, True)
                    self._add_finding("used_port", {"port": smb_port}, True)

                    return True
                except Exception as e:
                    # Log connection failure for this dialect, but do not print to stdout/stderr directly.
                    # This will be captured in the final JSON if no connection succeeds.
                    # print(f"Attempt with dialect {dialect} failed: {e}", file=sys.stderr)
                    continue  # Try next dialect

            # If all dialect attempts fail
            self._add_finding("smb_connection", {"message": "Failed to establish SMB connection with any dialect."},
                              False, "Connection refused or no anonymous access (ports 445).")
            return False
        except Exception as e:
            # Catch any other unexpected errors during connection attempt
            self._add_finding("smb_connection", {"message": "General SMB connection error."}, False, str(e))
            return False

    def _disconnect_smb(self):
        """Disconnects the SMB connection."""
        if self.smb_con:
            try:
                self.smb_con.logoff()
            except Exception as e:
                # Log off errors are typically non-critical for the main scan results.
                # print(f"Error during SMB logoff: {e}", file=sys.stderr)
                pass

    def _connect_dce_rpc(self, pipe_name, uuid, version_major=1, version_minor=0):
        """
        Establishes a DCE/RPC connection over SMB to a specific pipe.
        :param pipe_name: The name of the named pipe (e.g., '\\pipe\\samr').
        :param uuid: The MSRPC UUID of the interface (e.g., samr.MSRPC_UUID_SAMR).
        :param version_major: Major version of the interface.
        :param version_minor: Minor version of the interface.
        :return: A bound DCERPC_v5 object if successful, None otherwise.
        """
        try:
            # Ensure SMB connection is active before attempting RPC over SMB
            if not self.smb_con:
                self._add_finding(f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                                  {"message": "SMB connection not established, cannot open RPC pipe."}, False)
                return None

            # Create an SMB transport for RPC
            rpctransport = transport.SMBTransport(self.target_ip, self.target_ip, filename=pipe_name,
                                                  smb_connection=self.smb_con)

            # Get DCE/RPC client and bind to the interface
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuid, transfer_syntax=('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))  # Ndr format
            self._add_finding(f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                              {"message": f"DCE/RPC bound to {pipe_name} (UUID: {uuid})"}, True)
            return dce
        except Exception as e:
            self._add_finding(f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                              {"message": f"Failed to establish DCE/RPC connection for {pipe_name}."}, False, str(e))
            return None

    def perform_enumeration(self):
        """
        Performs various stages of SMB/NetBIOS enumeration using Impacket.
        """
        # 1. NetBIOS Name Resolution
        try:
            nb = NetBIOS()
            # Resolve host by IP, similar to nmblookup -A
            host_info = nb.gethostbyname(self.target_ip, timeout=5)  # Add a timeout for resolution
            self.results["findings"]["netbios_hostname"] = {
                "data": {
                    "hostname": host_info.get_hostname(),
                    "mac_address": host_info.get_mac(),
                    "ip_address": host_info.get_ip(),
                    "netbios_names": host_info.get_netbios_names()
                },
                "success": True,
                "error": None
            }
        except Exception as e:
            self._add_finding("netbios_hostname", {}, False, f"Failed to resolve NetBIOS name: {e}")

        # 2. Establish SMB Connection (required for further RPC calls)
        if not self._connect_smb():
            return  # Cannot proceed with RPC enumeration without SMB connection

        try:
            # 3. SMB Shares Enumeration
            shares = []
            try:
                for share in self.smb_con.listShares():
                    # Impacket returns bytes, decode them
                    share_name = share['shi1_netname'].decode('utf-16le').strip('\x00')
                    share_remark = share['shi1_remark'].decode('utf-16le').strip('\x00')
                    shares.append({"name": share_name, "remark": share_remark})
                self._add_finding("smb_shares", shares, True)
            except Exception as e:
                self._add_finding("smb_shares", [], False, f"Failed to list SMB shares: {e}")

            # 4. RPC Enumeration (Users, Groups, Domain Info, Password Policy)
            # Bind to SAMR (Security Account Manager Remote)
            self.dce_samr = self._connect_dce_rpc('\\pipe\\samr', samr.MSRPC_UUID_SAMR)
            if self.dce_samr:
                try:
                    # Open domain handle (null session)
                    resp_connect = samr.hSamrConnect(self.dce_samr)
                    serverHandle = resp_connect['ServerHandle']

                    # Lookup Builtin domain to get its handle
                    resp_lookup = samr.hSamrLookupDomainInSamServer(self.dce_samr, serverHandle, 'Builtin')
                    domainHandle = resp_lookup['DomainHandle']

                    # Enum Domain Users
                    users = []
                    try:
                        enum_handle = 0
                        while True:
                            resp_enum_users = samr.hSamrEnumDomainUsers(self.dce_samr, domainHandle, enum_handle, 500)
                            for user in resp_enum_users['Buffer']['Buffer']:
                                users.append({"rid": user['RelativeId'], "name": user['Name']})
                            enum_handle = resp_enum_users['EnumerationContext']
                            if resp_enum_users['Buffer']['Count'] == 0:
                                break
                        self._add_finding("samr_enum_domain_users", users, True)
                    except Exception as e:
                        self._add_finding("samr_enum_domain_users", [], False, f"Failed to enumerate domain users: {e}")

                    # Enum Domain Groups
                    groups = []
                    try:
                        enum_handle = 0
                        while True:
                            resp_enum_groups = samr.hSamrEnumDomainGroups(self.dce_samr, domainHandle, enum_handle, 500)
                            for group in resp_enum_groups['Buffer']['Buffer']:
                                groups.append({"rid": group['RelativeId'], "name": group['Name']})
                            enum_handle = resp_enum_groups['EnumerationContext']
                            if resp_enum_groups['Buffer']['Count'] == 0:
                                break
                        self._add_finding("samr_enum_domain_groups", groups, True)
                    except Exception as e:
                        self._add_finding("samr_enum_domain_groups", [], False,
                                          f"Failed to enumerate domain groups: {e}")

                    # Query Domain Info
                    try:
                        resp_query_info = samr.hSamrQueryInformationDomain(self.dce_samr, domainHandle,
                                                                           samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
                        domain_info = {
                            "name": resp_query_info['Buffer']['DomainGeneralInformation']['DomainName'],
                            "sid": str(resp_query_info['Buffer']['DomainGeneralInformation']['DomainSid'])
                        }
                        self._add_finding("samr_query_domain_info", domain_info, True)
                    except Exception as e:
                        self._add_finding("samr_query_domain_info", {}, False, f"Failed to query domain info: {e}")

                except Exception as e:
                    self._add_finding("samr_session", {}, False, f"SAMR session setup failed or RPC call error: {e}")
                finally:
                    if self.dce_samr:
                        try:
                            self.dce_samr.disconnect()
                        except:
                            pass

            # Bind to LSAD (Local Security Authority (Domain) Policy)
            self.dce_lsad = self._connect_dce_rpc('\\pipe\\lsarpc', lsad.MSRPC_UUID_LSAD)
            if self.dce_lsad:
                try:
                    # Open policy handle with required access
                    resp_open_policy = lsad.hLsarOpenPolicy2(self.dce_lsad,
                                                             lsad.POLICY_ACCESS.POLICY_VIEW_LOCAL_INFORMATION)
                    policyHandle = resp_open_policy['PolicyHandle']

                    # Get Password Policy
                    try:
                        resp_query_policy = lsad.hLsarQueryInformationPolicy(self.dce_lsad, policyHandle,
                                                                             lsad.POLICY_INFORMATION_CLASS.PolicyPasswordInformation)
                        password_policy = {
                            "MinPasswordLength": resp_query_policy['PolicyInformation']['PolicyPasswordInformation'][
                                'MinPasswordLength'],
                            "PasswordHistoryLength":
                                resp_query_policy['PolicyInformation']['PolicyPasswordInformation'][
                                    'PasswordHistoryLength'],
                            "PasswordProperties": resp_query_policy['PolicyInformation']['PolicyPasswordInformation'][
                                'PasswordProperties']  # Bitmask, needs decoding
                        }
                        self._add_finding("lsad_password_policy", password_policy, True)
                    except Exception as e:
                        self._add_finding("lsad_password_policy", {}, False, f"Failed to query password policy: {e}")
                except Exception as e:
                    self._add_finding("lsad_session", {}, False, f"LSAD session setup failed or RPC call error: {e}")

                finally:
                    if self.dce_lsad:
                        try:
                            self.dce_lsad.disconnect()
                        except:
                            pass

            # Bind to WKST (Workstation Service) - for session enumeration if possible.
            # This typically requires authentication or very specific configurations for anonymous access.
            # self.dce_wkst = self._connect_dce_rpc('\\pipe\\wkssvc', wkst.MSRPC_UUID_WKSSVC)
            self.dce_wkst = self._connect_dce_rpc('\\pipe\\wkssvc', wkst.MSRPC_UUID_WKST)

            if self.dce_wkst:
                try:
                    # WKST enumeration methods (e.g., NetWkstaUserEnum) usually require higher privileges.
                    # For a null session, this will often fail.
                    self._add_finding("wkst_session_attempt", {
                        "message": "Attempted to connect to WKST service. Enumeration of sessions/users via null session is generally restricted."},
                                      True)
                except Exception as e:
                    self._add_finding("wkst_session_attempt", {}, False, f"WKST session failed: {e}")
                finally:
                    if self.dce_wkst:
                        try:
                            self.dce_wkst.disconnect()
                        except:
                            pass

        finally:
            # Ensure SMB connection is always closed
            self._disconnect_smb()

    def get_results(self):
        """
        Returns the collected results as a dictionary.
        """
        return self.results