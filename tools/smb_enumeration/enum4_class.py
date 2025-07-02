import os

from impacket.dcerpc.v5 import transport, samr, lsad, wkst
from impacket.nmb import NetBIOS
from impacket.smbconnection import SMBConnection


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
        self.smb_port = 445
        self.results = {
            "target_ip": target_ip,
            "port": self.smb_port,
            "status": "success",
            "findings": {},
        }
        self.smb_con = None
        self.dce_samr = None
        self.dce_lsad = None
        self.dce_wkst = None

    def _add_finding(self, description, data, success=True, error=None):
        """Helper to add findings to the result dictionary."""
        self.results["findings"][description] = {
            "data": data,
            "success": success,
            "error": error,
        }

    def _connect_smb(self):
        """Establishes an SMB connection to the target."""
        try:
            # SMB v2/3 dialects are preferred.
            dialects = [
                "SMB3_11",
                "SMB3_02",
                "SMB3_00",
                "SMB2_10",
                "SMB2_02",
                "NT LM 0.12",
            ]  # Added NT LM 0.12 for older servers

            for dialect in dialects:
                try:
                    # Attempt connection with a specific dialect
                    self.smb_con = SMBConnection(
                        self.target_ip,
                        self.target_ip,
                        sess_port=self.smb_port,
                        preferredDialect=dialect,
                    )
                    # Attempt anonymous/null session login
                    self.smb_con.login("", "")
                    self._add_finding(
                        "smb_connection",
                        {
                            "message": f"SMB connection established with dialect {dialect}"
                        },
                        True,
                    )

                    return True
                except Exception:
                    continue

            # If all dialect attempts fail
            self._add_finding(
                "smb_connection",
                {"message": "Failed to establish SMB connection with any dialect."},
                False,
                "Connection refused or no anonymous access (ports 445).",
            )
            return False
        except Exception as e:
            self._add_finding(
                "smb_connection",
                {"message": "General SMB connection error."},
                False,
                str(e),
            )
            return False

    def _disconnect_smb(self):
        """Disconnects the SMB connection."""
        if self.smb_con:
            try:
                self.smb_con.logoff()
            except Exception:
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
                self._add_finding(
                    f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                    {
                        "message": "SMB connection not established, cannot open RPC pipe."
                    },
                    False,
                )
                return None

            # Create an SMB transport for RPC
            rpctransport = transport.SMBTransport(
                self.target_ip,
                self.target_ip,
                filename=pipe_name,
                smb_connection=self.smb_con,
            )

            # Get DCE/RPC client and bind to the interface
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(
                uuid, transfer_syntax=("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
            )  # Ndr format
            self._add_finding(
                f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                {"message": f"DCE/RPC bound to {pipe_name} (UUID: {uuid})"},
                True,
            )
            return dce
        except Exception as e:
            self._add_finding(
                f"dce_rpc_connect_{pipe_name.replace('\\pipe\\', '')}",
                {"message": f"Failed to establish DCE/RPC connection for {pipe_name}."},
                False,
                str(e),
            )
            return None

    def _enumerate_share_contents(self, share_name, path="\\", depth=0, max_depth=3):
        """
        Recursively enumerates the contents of an SMB share.
        Assumes read access has already been checked at the top level.
        :param share_name: The name of the share (e.g., 'C$').
        :param path: Current path within the share (e.g., '\\').
        :param depth: Current recursion depth.
        :param max_depth: Maximum recursion depth to prevent infinite loops.
        :return: List of dictionaries with file/folder info. Returns empty list if access denied or no contents.
        """
        if depth > max_depth:
            return [
                {"type": "info", "name": f"{path}...", "message": "Max depth reached"}
            ]

        contents = []
        try:
            files_and_dirs = self.smb_con.listPath(share_name, path + "*")
            for f in files_and_dirs:
                if f.is_directory() and f.get_longname() not in [".", ".."]:
                    sub_path = os.path.join(path, f.get_longname()).replace("/", "\\")
                    contents.append(
                        {
                            "type": "directory",
                            "name": sub_path,
                            "contents": self._enumerate_share_contents(
                                share_name, sub_path + "\\", depth + 1, max_depth
                            ),
                        }
                    )
                elif not f.is_directory():
                    contents.append(
                        {
                            "type": "file",
                            "name": os.path.join(path, f.get_longname()).replace(
                                "/", "\\"
                            ),
                            "size": f.get_filesize(),
                        }
                    )
        except Exception as e:
            # If listing fails at a deeper level (e.g., permission changes mid-way), capture it here.
            # This will show up in the contents list as an error for that specific path.
            if (
                depth == 0
            ):  # If it's the root of the share, and it failed despite initial check, something went wrong.
                return []
            else:  # If it's a sub-directory and failed
                contents.append({"type": "error", "name": path, "error": str(e)})
        return contents

    def perform_enumeration(self):
        """
        Performs various stages of SMB/NetBIOS enumeration using Impacket.
        """
        # 1. NetBIOS Name Resolution
        try:
            nb = NetBIOS()
            host_info = nb.gethostbyname(self.target_ip, timeout=5)
            self.results["findings"]["netbios_hostname"] = {
                "data": {
                    "hostname": host_info.get_hostname(),
                    "mac_address": host_info.get_mac(),
                    "ip_address": host_info.get_ip(),
                    "netbios_names": host_info.get_netbios_names(),
                },
                "success": True,
                "error": None,
            }
        except Exception as e:
            self._add_finding(
                "netbios_hostname", {}, False, f"Failed to resolve NetBIOS name: {e}"
            )

        # 2. Establish SMB Connection (required for further RPC calls and share enumeration)
        if not self._connect_smb():
            return

        try:
            # 3. SMB Shares Enumeration and Content Listing/Permission Checking
            shares_info = []
            processed_share_names = set()  # Set to keep track of processed share names

            try:
                shares = self.smb_con.listShares()
                for share in shares:
                    _share_name_raw = share["shi1_netname"]
                    if isinstance(_share_name_raw, bytes):
                        share_name = _share_name_raw.decode("utf-16le").strip("\x00")
                    else:
                        share_name = str(_share_name_raw).strip("\x00")

                    # --- LOGIC FOR DE-DUPLICATION ---
                    if share_name in processed_share_names:
                        continue

                    processed_share_names.add(share_name)
                    # --- END LOGIC ---

                    _share_remark_raw = share["shi1_remark"]
                    if isinstance(_share_remark_raw, bytes):
                        share_remark = _share_remark_raw.decode("utf-16le").strip(
                            "\x00"
                        )
                    else:
                        share_remark = str(_share_remark_raw).strip("\x00")

                    share_data = {"name": share_name, "remark": share_remark}

                    # --- LOGIC FOR PERMISSION CHECK & CONDITIONAL CONTENT LISTING ---
                    can_read = False
                    can_write = False
                    try:
                        # Attempt to list directory to check read access
                        self.smb_con.listPath(share_name, "\\*")
                        can_read = True
                    except Exception:
                        pass  # Read access denied

                    if can_read:
                        # Only try to write if we can read the directory (to ensure it exists)
                        temp_filename = f"impacket_test_{os.urandom(4).hex()}.tmp"
                        test_file_path = os.path.join("\\", temp_filename).replace(
                            "/", "\\"
                        )  # Root of share
                        try:
                            file_contents = b"test"
                            self.smb_con.createFile(share_name, test_file_path)
                            self.smb_con.writeFile(
                                share_name, test_file_path, file_contents
                            )
                            self.smb_con.deleteFile(share_name, test_file_path)
                            can_write = True
                        except Exception:
                            pass

                    share_data["permission_status"] = (
                        f"{'Read' if can_read else 'NoRead'}/{'Write' if can_write else 'NoWrite'}"
                    )

                    if can_read:
                        share_data["contents"] = self._enumerate_share_contents(
                            share_name
                        )
                    else:
                        share_data["contents"] = []
                        # --- END LOGIC ---

                    shares_info.append(share_data)

                self._add_finding("smb_shares_detailed", shares_info, True)

            except Exception as e:
                self._add_finding(
                    "smb_shares_detailed",
                    [],
                    False,
                    f"Failed to list or enumerate SMB shares: {e}",
                )

            # 4. RPC Enumeration (Users, Groups, Domain Info, Password Policy) - Existing logic
            self.dce_samr = self._connect_dce_rpc("\\pipe\\samr", samr.MSRPC_UUID_SAMR)
            if self.dce_samr:
                try:
                    resp_connect = samr.hSamrConnect(self.dce_samr)
                    serverHandle = resp_connect["ServerHandle"]

                    resp_lookup = samr.hSamrLookupDomainInSamServer(
                        self.dce_samr, serverHandle, "Builtin"
                    )
                    domainHandle = resp_lookup["DomainHandle"]

                    users = []
                    try:
                        enum_handle = 0
                        while True:
                            resp_enum_users = samr.hSamrEnumDomainUsers(
                                self.dce_samr, domainHandle, enum_handle, 500
                            )
                            for user in resp_enum_users["Buffer"]["Buffer"]:
                                users.append(
                                    {"rid": user["RelativeId"], "name": user["Name"]}
                                )
                            enum_handle = resp_enum_users["EnumerationContext"]
                            if resp_enum_users["Buffer"]["Count"] == 0:
                                break
                        self._add_finding("samr_enum_domain_users", users, True)
                    except Exception as e:
                        self._add_finding(
                            "samr_enum_domain_users",
                            [],
                            False,
                            f"Failed to enumerate domain users: {e}",
                        )

                    groups = []
                    try:
                        enum_handle = 0
                        while True:
                            resp_enum_groups = samr.hSamrEnumDomainGroups(
                                self.dce_samr, domainHandle, enum_handle, 500
                            )
                            for group in resp_enum_groups["Buffer"]["Buffer"]:
                                groups.append(
                                    {"rid": group["RelativeId"], "name": group["Name"]}
                                )
                            enum_handle = resp_enum_groups["EnumerationContext"]
                            if resp_enum_groups["Buffer"]["Count"] == 0:
                                break
                        self._add_finding("samr_enum_domain_groups", groups, True)
                    except Exception as e:
                        self._add_finding(
                            "samr_enum_domain_groups",
                            [],
                            False,
                            f"Failed to enumerate domain groups: {e}",
                        )

                    try:
                        resp_query_info = samr.hSamrQueryInformationDomain(
                            self.dce_samr,
                            domainHandle,
                            samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation,
                        )
                        domain_info = {
                            "name": resp_query_info["Buffer"][
                                "DomainGeneralInformation"
                            ]["DomainName"],
                            "sid": str(
                                resp_query_info["Buffer"]["DomainGeneralInformation"][
                                    "DomainSid"
                                ]
                            ),
                        }
                        self._add_finding("samr_query_domain_info", domain_info, True)
                    except Exception as e:
                        self._add_finding(
                            "samr_query_domain_info",
                            {},
                            False,
                            f"Failed to query domain info: {e}",
                        )

                except Exception as e:
                    self._add_finding(
                        "samr_session",
                        {},
                        False,
                        f"SAMR session setup failed or RPC call error: {e}",
                    )
                finally:
                    if self.dce_samr:
                        try:
                            self.dce_samr.disconnect()
                        except Exception:
                            pass

            self.dce_lsad = self._connect_dce_rpc(
                "\\pipe\\lsarpc", lsad.MSRPC_UUID_LSAD
            )
            if self.dce_lsad:
                try:
                    resp_open_policy = lsad.hLsarOpenPolicy2(
                        self.dce_lsad, lsad.POLICY_ACCESS.POLICY_VIEW_LOCAL_INFORMATION
                    )
                    policyHandle = resp_open_policy["PolicyHandle"]

                    try:
                        resp_query_policy = lsad.hLsarQueryInformationPolicy(
                            self.dce_lsad,
                            policyHandle,
                            lsad.POLICY_INFORMATION_CLASS.PolicyPasswordInformation,
                        )
                        password_policy = {
                            "MinPasswordLength": resp_query_policy["PolicyInformation"][
                                "PolicyPasswordInformation"
                            ]["MinPasswordLength"],
                            "PasswordHistoryLength": resp_query_policy[
                                "PolicyInformation"
                            ]["PolicyPasswordInformation"]["PasswordHistoryLength"],
                            "PasswordProperties": resp_query_policy[
                                "PolicyInformation"
                            ]["PolicyPasswordInformation"]["PasswordProperties"],
                        }
                        self._add_finding("lsad_password_policy", password_policy, True)
                    except Exception as e:
                        self._add_finding(
                            "lsad_password_policy",
                            {},
                            False,
                            f"Failed to query password policy: {e}",
                        )
                except Exception as e:
                    self._add_finding(
                        "lsad_session",
                        {},
                        False,
                        f"LSAD session setup failed or RPC call error: {e}",
                    )

                finally:
                    if self.dce_lsad:
                        try:
                            self.dce_lsad.disconnect()
                        except Exception:
                            pass

            self.dce_wkst = self._connect_dce_rpc(
                "\\pipe\\wkssvc", wkst.MSRPC_UUID_WKST
            )

            if self.dce_wkst:
                try:
                    self._add_finding(
                        "wkst_session_attempt",
                        {
                            "message": "Attempted to connect to WKST service. Enumeration of sessions/users via null session is generally restricted."
                        },
                        True,
                    )
                except Exception as e:
                    self._add_finding(
                        "wkst_session_attempt", {}, False, f"WKST session failed: {e}"
                    )
                finally:
                    if self.dce_wkst:
                        try:
                            self.dce_wkst.disconnect()
                        except Exception:
                            pass

        finally:
            self._disconnect_smb()

    def get_results(self):
        return self.results
