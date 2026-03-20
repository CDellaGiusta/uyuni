/*
 * Copyright (c) 2024 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.suse.manager.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.hibernate.LookupException;
import com.redhat.rhn.common.security.PermissionException;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.CoCoAttestationAction;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.MinionServerFactoryTest;
import com.redhat.rhn.domain.server.Pillar;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerFactoryTest;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.taskomatic.TaskomaticApiException;
import com.redhat.rhn.testing.JMockBaseTestCaseWithUser;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import com.suse.manager.model.attestation.AttestationFactory;
import com.suse.manager.model.attestation.CoCoAttestationResult;
import com.suse.manager.model.attestation.CoCoAttestationStatus;
import com.suse.manager.model.attestation.CoCoEnvironmentType;
import com.suse.manager.model.attestation.ServerCoCoAttestationConfig;
import com.suse.manager.model.attestation.ServerCoCoAttestationReport;
import com.suse.manager.webui.services.pillar.MinionGeneralPillarGenerator;
import com.suse.manager.webui.utils.salt.custom.CoCoAmdEpycAttestationRequestData;
import com.suse.manager.webui.utils.salt.custom.CoCoAttestationRequestData;
import com.suse.manager.webui.utils.salt.custom.CoCoAttestationRequestDataCarlo;
import com.suse.manager.webui.utils.salt.custom.CoCoAttestationRequestDataCarlo2;
import com.suse.manager.webui.utils.salt.custom.CoCoSecureBootAttestationRequestData;
import com.suse.salt.netapi.results.CmdResult;
import com.suse.salt.netapi.results.StateApplyResult;
import com.suse.utils.Json;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import org.jmock.Expectations;
import org.jmock.imposters.ByteBuddyClassImposteriser;
import org.jmock.lib.concurrent.Synchroniser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class AttestationManagerTest extends JMockBaseTestCaseWithUser {

    private User user2;
    private Server server;
    private Server server2;
    private Server server3;
    private Server server4;
    private AttestationManager mgr;
    private static TaskomaticApi taskomaticApi;


    private static String saltStateJsonInputString = """
                {
                   "saltutil_|-sync_states_|-sync_states_|-sync_states":{
                      "name":"sync_states",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"No updates to sync",
                      "__sls__":"util.syncstates",
                      "__run_num__":0,
                      "start_time":"09:51:03.373782",
                      "duration":104.521,
                      "__id__":"sync_states"
                   },
                   "pkg_|-mgr_absent_ca_package_|-rhn-org-trusted-ssl-cert_|-removed":{
                      "name":"rhn-org-trusted-ssl-cert",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"All specified packages are already absent",
                      "__sls__":"certs",
                      "__run_num__":1,
                      "start_time":"09:51:03.992424",
                      "duration":3.079,
                      "__id__":"mgr_absent_ca_package"
                   },
                   "file_|-mgr_ca_cert_|-/etc/pki/trust/anchors/RHN-ORG-TRUSTED-SSL-CERT_|-managed":{
                      "changes":{
                
                      },
                      "comment":"File /etc/pki/trust/anchors/RHN-ORG-TRUSTED-SSL-CERT is in the correct state",
                      "name":"/etc/pki/trust/anchors/RHN-ORG-TRUSTED-SSL-CERT",
                      "result":true,
                      "__sls__":"certs",
                      "__run_num__":2,
                      "start_time":"09:51:03.996701",
                      "duration":14.323,
                      "__id__":"mgr_ca_cert"
                   },
                   "cmd_|-update-ca-certificates_|-/usr/sbin/update-ca-certificates_|-run":{
                      "changes":{
                
                      },
                      "result":true,
                      "duration":0.002,
                      "start_time":"09:51:04.011737",
                      "comment":"State was not run because none of the onchanges reqs changed",
                      "__state_ran__":false,
                      "__run_num__":3,
                      "__sls__":"certs",
                      "__id__":"update-ca-certificates",
                      "name":"/usr/sbin/update-ca-certificates"
                   },
                   "file_|-mgr_proxy_ca_cert_symlink_|-/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT_|-symlink":{
                      "result":true,
                      "name":"/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT",
                      "changes":{
                
                      },
                      "comment":"onlyif condition is false",
                      "__sls__":"certs",
                      "__id__":"mgr_proxy_ca_cert_symlink",
                      "skip_watch":true,
                      "__run_num__":4,
                      "start_time":"09:51:04.011780",
                      "duration":240.799
                   },
                   "file_|-mgr_deploy_tools_uyuni_key_|-/etc/pki/rpm-gpg/uyuni-tools-gpg-pubkey-0d20833e.key_|-managed":{
                      "changes":{
                
                      },
                      "comment":"File /etc/pki/rpm-gpg/uyuni-tools-gpg-pubkey-0d20833e.key is in the correct state",
                      "name":"/etc/pki/rpm-gpg/uyuni-tools-gpg-pubkey-0d20833e.key",
                      "result":true,
                      "__sls__":"channels.gpg-keys",
                      "__run_num__":5,
                      "start_time":"09:51:04.252657",
                      "duration":14.5,
                      "__id__":"mgr_deploy_tools_uyuni_key"
                   },
                   "file_|-mgr_deploy_suse_addon_key_|-/etc/pki/rpm-gpg/suse-addon-97a636db0bad8ecc.key_|-managed":{
                      "changes":{
                
                      },
                      "comment":"File /etc/pki/rpm-gpg/suse-addon-97a636db0bad8ecc.key is in the correct state",
                      "name":"/etc/pki/rpm-gpg/suse-addon-97a636db0bad8ecc.key",
                      "result":true,
                      "__sls__":"channels.gpg-keys",
                      "__run_num__":6,
                      "start_time":"09:51:04.267225",
                      "duration":13.196,
                      "__id__":"mgr_deploy_suse_addon_key"
                   },
                   "file_|-mgr_deploy_suse16_gpg_key_|-/etc/pki/rpm-gpg/suse16-gpg-pubkey-09d9ea69.key_|-managed":{
                      "changes":{
                
                      },
                      "comment":"File /etc/pki/rpm-gpg/suse16-gpg-pubkey-09d9ea69.key is in the correct state",
                      "name":"/etc/pki/rpm-gpg/suse16-gpg-pubkey-09d9ea69.key",
                      "result":true,
                      "__sls__":"channels.gpg-keys",
                      "__run_num__":7,
                      "start_time":"09:51:04.280505",
                      "duration":13.293,
                      "__id__":"mgr_deploy_suse16_gpg_key"
                   },
                   "file_|-mgrchannels_repo_|-/etc/zypp/repos.d/susemanager:channels.repo_|-managed":{
                      "changes":{
                
                      },
                      "comment":"File /etc/zypp/repos.d/susemanager:channels.repo is in the correct state",
                      "name":"/etc/zypp/repos.d/susemanager:channels.repo",
                      "result":true,
                      "__sls__":"channels",
                      "__run_num__":8,
                      "start_time":"09:51:04.293915",
                      "duration":43.894,
                      "__id__":"mgrchannels_repo"
                   },
                   "product_|-mgrchannels_install_products_|-mgrchannels_install_products_|-all_installed":{
                      "name":"mgrchannels_install_products",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"All subscribed products are already installed",
                      "__sls__":"channels",
                      "__run_num__":9,
                      "start_time":"09:51:04.338216",
                      "duration":431.093,
                      "__id__":"mgrchannels_install_products"
                   },
                   "pkg_|-mgrchannels_inst_suse_build_key_|-suse-build-key_|-installed":{
                      "name":"suse-build-key",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"All specified packages are already installed",
                      "__sls__":"channels",
                      "__run_num__":10,
                      "start_time":"09:51:04.769675",
                      "duration":1965.43,
                      "__id__":"mgrchannels_inst_suse_build_key"
                   },
                   "file_|-mgr_create_attestdir_|-/tmp/cocoattest_|-directory":{
                      "name":"/tmp/cocoattest",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"The directory /tmp/cocoattest is in the correct state",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":11,
                      "start_time":"09:51:06.735206",
                      "duration":0.589,
                      "__id__":"mgr_create_attestdir"
                   },
                   "pkg_|-mgr_inst_snpguest_|-mgr_inst_snpguest_|-latest":{
                      "name":"mgr_inst_snpguest",
                      "changes":{
                
                      },
                      "result":true,
                      "comment":"All packages are up-to-date (mokutil, snpguest).",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":12,
                      "start_time":"09:51:06.735880",
                      "duration":378.838,
                      "__id__":"mgr_inst_snpguest"
                   },
                   "cmd_|-mgr_write_request_data_|-ls -l_|-run":{
                      "name":"ls -l",
                      "changes":{
                         "pid":2742,
                         "retcode":0,
                         "stdout":"total 4\\ndrwxr-xr-x  2 root root    6 Mar 15  2022 bin\\ndrwxr-xr-x 21 root root 4096 Feb 24 18:29 salt",
                         "stderr":""
                      },
                      "result":true,
                      "comment":"Command \\"ls -l\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":13,
                      "start_time":"09:51:07.114915",
                      "duration":6.539,
                      "__id__":"mgr_write_request_data"
                   },
                   "cmd_|-mgr_create_snpguest_report_|-ls -l_|-run":{
                      "name":"ls -l",
                      "changes":{
                         "pid":2743,
                         "retcode":0,
                         "stdout":"total 4\\ndrwxr-xr-x  2 root root    6 Mar 15  2022 bin\\ndrwxr-xr-x 21 root root 4096 Feb 24 18:29 salt",
                         "stderr":""
                      },
                      "result":true,
                      "comment":"Command \\"ls -l\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":14,
                      "start_time":"09:51:07.121630",
                      "duration":2.207,
                      "__id__":"mgr_create_snpguest_report"
                   },
                   "cmd_|-mgr_snpguest_report_|-/usr/bin/cat /tmp/cocoattest/report.bin | /usr/bin/base64_|-run":{
                      "name":"/usr/bin/cat /tmp/cocoattest/report.bin | /usr/bin/base64",
                      "changes":{
                         "pid":2744,
                         "retcode":0,
                         "stdout":"BQAAAAAAAAAAAAMCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAE\\nAAAAAAAd3icAAAAAAAAABAAAAAAAAACvUTwurA60JuLr4saoUcqnlRByTSye2RoG7cm7aV3GFDM8\\nhBVP1bRVv+xZ+xgMnSxeXtRHKWQWIJeOKWzdHrjKUH6C0n6luVHddlo+sxul9YJnOzAdaYPe1ILT\\n/rBmy2iXnx8R/t6XaHN006JQAqFfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0BzK9Zd/WojFnYDcZSyMuFyK38wdR\\nFG1y0mG8SdJ85///////////////////////////////////////////BAAAAAAAHd4ZAQEAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAHd4BOgEAAToBAAQAAAAAAB3eDwAAAAAAAAAP\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAl5RQN5FIiFMGs4Ud\\nFRQ/It0+g1ccaH0sbEgIVvRsxZMs5UwjpgqEwwqXKJ+vWUP3AAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAJFiRN+f4t0/lz6CxHmVe4DEl+YWRZ/U/jacsJCUt7XqpIHqeJUr0u4F4s3NIMTZGAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "stderr":""
                      },
                      "result":true,
                      "comment":"Command \\"/usr/bin/cat /tmp/cocoattest/report.bin | /usr/bin/base64\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":15,
                      "start_time":"09:51:07.123989",
                      "duration":1.806,
                      "__id__":"mgr_snpguest_report"
                   },
                   "cmd_|-mgr_create_vlek_certificate_|-ls -l_|-run":{
                      "name":"ls -l",
                      "changes":{
                         "pid":2747,
                         "retcode":0,
                         "stdout":"total 4\\ndrwxr-xr-x  2 root root    6 Mar 15  2022 bin\\ndrwxr-xr-x 21 root root 4096 Feb 24 18:29 salt",
                         "stderr":""
                      },
                      "result":true,
                      "comment":"Command \\"ls -l\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":16,
                      "start_time":"09:51:07.125867",
                      "duration":1.497,
                      "__id__":"mgr_create_vlek_certificate"
                   },
                   "cmd_|-mgr_vlek_certificate_|-/usr/bin/cat /tmp/cocoattest/vlek.pem_|-run":{
                      "name":"/usr/bin/cat /tmp/cocoattest/vlek.pem",
                      "changes":{
                         "pid":2748,
                         "retcode":0,
                         "stdout":"-----BEGIN CERTIFICATE-----\\nMIIFIzCCAtegAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA\\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwgYAxFDASBgNVBAsM\\nC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmEx\\nCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMRcw\\nFQYDVQQDDA5TRVYtVkxFSy1NaWxhbjAeFw0yNjAzMDkxOTMwMDVaFw0yNzAzMDkx\\nOTMwMDVaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIG\\nA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNl\\nZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkxFSzB2MBAGByqGSM49AgEG\\nBSuBBAAiA2IABE/rO0PxEkKVu5SAX9Fv+h1pF0r+wWNmNO+DLcMENz2IOaqYiS6s\\nwJjXThFjsjIx5mdy42ozh33DIC+b02LmGScVQrREUL0h5KR4Qd5+BTiO+UDBb8Xd\\n/p8rzpTQn+foEKOB8jCB7zAQBgkrBgEEAZx4AQEEAwIBADAUBgkrBgEEAZx4AQIE\\nBxYFTWlsYW4wEQYKKwYBBAGceAEDAQQDAgEEMBEGCisGAQQBnHgBAwIEAwIBADAR\\nBgorBgEEAZx4AQMEBAMCAQAwEQYKKwYBBAGceAEDBQQDAgEAMBEGCisGAQQBnHgB\\nAwYEAwIBADARBgorBgEEAZx4AQMHBAMCAQAwEQYKKwYBBAGceAEDAwQDAgEdMBIG\\nCisGAQQBnHgBAwgEBAICAN4wLAYJKwYBBAGceAEFBB8WHUNOPWNjLXVzLWVhc3Qt\\nMi5hbWF6b25hd3MuY29tMEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQCh\\nHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMAOCAgEAezLRKlKoxDhJ\\n9gGLDoIhruKSWJcwMHPn6E/aJzJvpDaYfb12ACKHyiMsm5htk6+lL9Kse544pmhh\\nUm/hxlpUNXiF+61obfKcaxp11Q2hzC/hTyLYpse6IXskLq6OH+DXzrcw0X30t3YI\\niUqzCGszbeTBy4uUOULxz3XbSUYFsKwsk9oMuo7isOUM3INiMiOTq91THlp6ZSVJ\\nDLIpW8v17DSL7yfJsvyLKsvtL7YjohFsOJe/qr/ttVSLC9WJmnxMxaxtgLSVGwCN\\nTHsx6646R7SAPRVXpdOd4f+Gfj4Dk1eiELs1L85Qm0tChDLrLLO31X9cwPxg6fjd\\nZ3sgqZrOv9Up2EiiX3uzH9pjuek9KZw8BvbNmkABURnj2QVKkANKWeVwJ2OI9xmb\\nKnLDQp+t3Q6gTcdPdcjSsAkT0JijpzamEmIPLdBobgVHAcxCxRhBILmJWQcU8V8R\\ng2+n/Zs8gpuGaCj0j8s8YDq7+sgy0/5CsDgAhU7+4HqzBTPbhOCNAI9uptU6v0xo\\nDLzldXmVJQaGWp6zQ+WB29ZnFrF4UE85+os3uIwc6uEPBjh3bjmhTwa3I7LWRWld\\nRyoJUuLnBIdTJYVIkgrYJ47LfI3akZxUM0D+FpqawemnHOTT1z8ee1wj7wnE6nS2\\nX0R7cJNthweU48At2ZfRIuPYvu9av2Y=\\n-----END CERTIFICATE-----",
                         "stderr":""
                      },
                      "result":true,
                      "comment":"Command \\"/usr/bin/cat /tmp/cocoattest/vlek.pem\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":17,
                      "start_time":"09:51:07.127515",
                      "duration":1.291,
                      "__id__":"mgr_vlek_certificate"
                   },
                   "cmd_|-mgr_secureboot_enabled_|-/usr/bin/mokutil --sb-state_|-run":{
                      "name":"/usr/bin/mokutil --sb-state",
                      "changes":{
                         "pid":2749,
                         "retcode":1,
                         "stdout":"",
                         "stderr":"EFI variables are not supported on this system"
                      },
                      "result":false,
                      "comment":"Command \\"/usr/bin/mokutil --sb-state\\" run",
                      "__sls__":"manager_org_1.test",
                      "__run_num__":18,
                      "start_time":"09:51:07.128844",
                      "duration":2.288,
                      "__id__":"mgr_secureboot_enabled"
                   }
                }
                
                """;

    private static String expectedBase64ReportData = """
                BQAAAAAAAAAAAAMCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAE
                AAAAAAAd3icAAAAAAAAABAAAAAAAAACvUTwurA60JuLr4saoUcqnlRByTSye2RoG7cm7aV3GFDM8
                hBVP1bRVv+xZ+xgMnSxeXtRHKWQWIJeOKWzdHrjKUH6C0n6luVHddlo+sxul9YJnOzAdaYPe1ILT
                /rBmy2iXnx8R/t6XaHN006JQAqFfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0BzK9Zd/WojFnYDcZSyMuFyK38wdR
                FG1y0mG8SdJ85///////////////////////////////////////////BAAAAAAAHd4ZAQEAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAHd4BOgEAAToBAAQAAAAAAB3eDwAAAAAAAAAP
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAl5RQN5FIiFMGs4Ud
                FRQ/It0+g1ccaH0sbEgIVvRsxZMs5UwjpgqEwwqXKJ+vWUP3AAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAJFiRN+f4t0/lz6CxHmVe4DEl+YWRZ/U/jacsJCUt7XqpIHqeJUr0u4F4s3NIMTZGAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""";

    private static String expectedVlekCertificate = """
                -----BEGIN CERTIFICATE-----
                MIIFIzCCAtegAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA
                oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwgYAxFDASBgNVBAsM
                C0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmEx
                CzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMRcw
                FQYDVQQDDA5TRVYtVkxFSy1NaWxhbjAeFw0yNjAzMDkxOTMwMDVaFw0yNzAzMDkx
                OTMwMDVaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIG
                A1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNl
                ZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkxFSzB2MBAGByqGSM49AgEG
                BSuBBAAiA2IABE/rO0PxEkKVu5SAX9Fv+h1pF0r+wWNmNO+DLcMENz2IOaqYiS6s
                wJjXThFjsjIx5mdy42ozh33DIC+b02LmGScVQrREUL0h5KR4Qd5+BTiO+UDBb8Xd
                /p8rzpTQn+foEKOB8jCB7zAQBgkrBgEEAZx4AQEEAwIBADAUBgkrBgEEAZx4AQIE
                BxYFTWlsYW4wEQYKKwYBBAGceAEDAQQDAgEEMBEGCisGAQQBnHgBAwIEAwIBADAR
                BgorBgEEAZx4AQMEBAMCAQAwEQYKKwYBBAGceAEDBQQDAgEAMBEGCisGAQQBnHgB
                AwYEAwIBADARBgorBgEEAZx4AQMHBAMCAQAwEQYKKwYBBAGceAEDAwQDAgEdMBIG
                CisGAQQBnHgBAwgEBAICAN4wLAYJKwYBBAGceAEFBB8WHUNOPWNjLXVzLWVhc3Qt
                Mi5hbWF6b25hd3MuY29tMEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQCh
                HDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMAOCAgEAezLRKlKoxDhJ
                9gGLDoIhruKSWJcwMHPn6E/aJzJvpDaYfb12ACKHyiMsm5htk6+lL9Kse544pmhh
                Um/hxlpUNXiF+61obfKcaxp11Q2hzC/hTyLYpse6IXskLq6OH+DXzrcw0X30t3YI
                iUqzCGszbeTBy4uUOULxz3XbSUYFsKwsk9oMuo7isOUM3INiMiOTq91THlp6ZSVJ
                DLIpW8v17DSL7yfJsvyLKsvtL7YjohFsOJe/qr/ttVSLC9WJmnxMxaxtgLSVGwCN
                THsx6646R7SAPRVXpdOd4f+Gfj4Dk1eiELs1L85Qm0tChDLrLLO31X9cwPxg6fjd
                Z3sgqZrOv9Up2EiiX3uzH9pjuek9KZw8BvbNmkABURnj2QVKkANKWeVwJ2OI9xmb
                KnLDQp+t3Q6gTcdPdcjSsAkT0JijpzamEmIPLdBobgVHAcxCxRhBILmJWQcU8V8R
                g2+n/Zs8gpuGaCj0j8s8YDq7+sgy0/5CsDgAhU7+4HqzBTPbhOCNAI9uptU6v0xo
                DLzldXmVJQaGWp6zQ+WB29ZnFrF4UE85+os3uIwc6uEPBjh3bjmhTwa3I7LWRWld
                RyoJUuLnBIdTJYVIkgrYJ47LfI3akZxUM0D+FpqawemnHOTT1z8ee1wj7wnE6nS2
                X0R7cJNthweU48At2ZfRIuPYvu9av2Y=
                -----END CERTIFICATE-----""";

    String expectedSecureBootResult = "EFI variables are not supported on this system";

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        context.setThreadingPolicy(new Synchroniser());
        setImposteriser(ByteBuddyClassImposteriser.INSTANCE);
        user2 = UserTestUtils.createUser("user2", user.getOrg().getId());
        server = ServerFactoryTest.createTestServer(user, true);
        server2 = ServerFactoryTest.createTestServer(user2, true);
        server3 = ServerFactoryTest.createTestServer(user, true);
        server4 = ServerFactoryTest.createTestServer(user2, true);
        mgr = new AttestationManager(new AttestationFactory(), getTaskomaticApi());
    }

    @Test
    public void testCreateAttestationConfiguration() {
        assertThrows(PermissionException.class,
                () -> mgr.createConfig(user2, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true));

        ServerCoCoAttestationConfig cnf = mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        assertNotNull(cnf);
    }

    @Test
    public void testInitializeAttestationReport() {
        assertThrows(PermissionException.class, () -> mgr.initializeReport(user2, server));
        assertThrows(LookupException.class, () -> mgr.initializeReport(user, server));

        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        ServerCoCoAttestationReport report = mgr.initializeReport(user, server);
        assertNotNull(report);
    }

    @Test
    public void testInitializeAttestationResults() {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        ServerCoCoAttestationReport report = mgr.initializeReport(user, server);

        ServerCoCoAttestationReport brokenReport = new ServerCoCoAttestationReport();
        assertThrows(LookupException.class, () -> mgr.initializeResults(brokenReport));

        mgr.initializeResults(report);
        List<CoCoAttestationResult> results = report.getResults();
        assertFalse(results.isEmpty());
    }

    @Test
    public void testCreateAttestationAction() throws TaskomaticApiException {
        MinionServer minion = MinionServerFactoryTest.createTestMinionServer(user);
        mgr.createConfig(user, minion, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        Date now = new Date();
        CoCoAttestationAction action = mgr.scheduleAttestationAction(user, minion, now);
        assertNotNull(action);

        AttestationFactory f = new AttestationFactory();
        Optional<ServerCoCoAttestationReport> latestReport = f.lookupLatestReportByServer(minion);
        Map<String, Object> inData = latestReport.orElse(new ServerCoCoAttestationReport()).getInData();
        assertNotNull(inData);
        String nonceReport = (String) inData.getOrDefault("nonce", "not in report");
        Pillar pillar = minion.getPillarByCategory(MinionGeneralPillarGenerator.CATEGORY).orElse(new Pillar());
        Map<String, Object> attestationData = (Map<String, Object>) pillar.getPillar()
                .getOrDefault("attestation_data", new HashMap<>());
        String noncePillar = (String) attestationData.getOrDefault("nonce", "not in pillar");
        assertEquals(nonceReport, noncePillar);
        assertEquals("KVM_AMD_EPYC_GENOA",
                attestationData.getOrDefault("environment_type", "environment_type not found"));
    }

    @Test
    public void testAttestationRequestDataParsing() {
        JsonElement jsonResult = JsonParser.parseString(saltStateJsonInputString);

        //========================================
        // test actual class CoCoAttestationRequestData
        CoCoAttestationRequestData requestData = Json.GSON.fromJson(jsonResult, CoCoAttestationRequestData.class);

        assertTrue(requestData.getSnpguestReport().isPresent());
        assertEquals(expectedBase64ReportData, requestData.getSnpguestReport().get().getChanges().getStdout());

        assertTrue(requestData.getVlekCertificate().isPresent());
        assertEquals(expectedVlekCertificate, requestData.getVlekCertificate().get().getChanges().getStdout());

        assertTrue(requestData.getSecureBoot().isPresent());
        assertEquals(expectedSecureBootResult, requestData.getSecureBoot().get().getChanges().getStderr());

        Map<String, Object> requestDataMap = requestData.asMap();
        assertEquals(3, requestDataMap.size());
        assertEquals(expectedBase64ReportData, requestDataMap.get("mgr_snpguest_report"));
        assertEquals(expectedVlekCertificate, requestDataMap.get("mgr_vlek_certificate"));
        assertEquals(expectedSecureBootResult, requestDataMap.get("mgr_secureboot_enabled"));


        //========================================
        //TEST first solution CoCoAttestationRequestDataCarlo

        CoCoAttestationRequestDataCarlo requestDataCarlo = new CoCoAttestationRequestDataCarlo();
        requestDataCarlo.parse(jsonResult);

        assertTrue(requestDataCarlo.getSnpguestReport().isPresent());
        assertEquals(expectedBase64ReportData, requestDataCarlo.getSnpguestReport().get().getChanges().getStdout());

        assertTrue(requestDataCarlo.getVlekCertificate().isPresent());
        assertEquals(expectedVlekCertificate, requestDataCarlo.getVlekCertificate().get().getChanges().getStdout());

        assertTrue(requestDataCarlo.getSecureBoot().isPresent());
        assertEquals(expectedSecureBootResult, requestDataCarlo.getSecureBoot().get().getChanges().getStderr());

        Map<String, Object> requestDataCarloMap = requestDataCarlo.asMap();
        assertEquals(3, requestDataCarloMap.size());
        assertEquals(expectedBase64ReportData, requestDataCarloMap.get("mgr_snpguest_report"));
        assertEquals(expectedVlekCertificate, requestDataCarloMap.get("mgr_vlek_certificate"));
        assertEquals(expectedSecureBootResult, requestDataCarloMap.get("mgr_secureboot_enabled"));

        //========================================
        //TEST second solution CoCoAttestationRequestDataCarlo2

        CoCoAttestationRequestDataCarlo2 requestDataCarlo2 = new CoCoAttestationRequestDataCarlo2();
        requestDataCarlo2.parse(jsonResult);

        //assertTrue(requestDataCarlo2.getSnpguestReport().isPresent());
        assertTrue(requestDataCarlo2.getResult(CoCoAmdEpycAttestationRequestData.SNP_GUEST_REPORT_KEY).isPresent());
        //assertEquals(expectedBase64ReportData, requestDataCarlo2.getSnpguestReport().get().getChanges().getStdout());
        assertEquals(expectedBase64ReportData, requestDataCarlo2.getResult(CoCoAmdEpycAttestationRequestData.SNP_GUEST_REPORT_KEY).get().getChanges().getStdout());

        //assertTrue(requestDataCarlo2.getVlekCertificate().isPresent());
        assertTrue(requestDataCarlo2.getResult(CoCoAmdEpycAttestationRequestData.VLEK_CERTIFICATE_KEY).isPresent());
        //assertEquals(expectedVlekCertificate, requestDataCarlo2.getVlekCertificate().get().getChanges().getStdout());
        assertEquals(expectedVlekCertificate, requestDataCarlo2.getResult(CoCoAmdEpycAttestationRequestData.VLEK_CERTIFICATE_KEY).get().getChanges().getStdout());

        //assertTrue(requestDataCarlo2.getSecureBoot().isPresent());
        assertTrue(requestDataCarlo2.getResult(CoCoSecureBootAttestationRequestData.SECURE_BOOT_ENABLED_KEY).isPresent());
        //assertEquals(expectedSecureBootResult, requestDataCarlo2.getSecureBoot().get().getChanges().getStderr());
        assertEquals(expectedSecureBootResult, requestDataCarlo2.getResult(CoCoSecureBootAttestationRequestData.SECURE_BOOT_ENABLED_KEY).get().getChanges().getStderr());

        Map<String, Object> requestDataCarlo2Map = requestDataCarlo2.asMap();
        assertEquals(3, requestDataCarlo2Map.size());
        assertEquals(expectedBase64ReportData, requestDataCarlo2Map.get(CoCoAmdEpycAttestationRequestData.SNP_GUEST_REPORT_KEY));
        assertEquals(expectedVlekCertificate, requestDataCarlo2Map.get(CoCoAmdEpycAttestationRequestData.VLEK_CERTIFICATE_KEY));
        assertEquals(expectedSecureBootResult, requestDataCarlo2Map.get(CoCoSecureBootAttestationRequestData.SECURE_BOOT_ENABLED_KEY));

        Map<String, Object> requestDataCarlo2MapAlternative = requestDataCarlo2.asMapAlternative();
        assertEquals(3, requestDataCarlo2MapAlternative.size());
        assertEquals(expectedBase64ReportData, requestDataCarlo2MapAlternative.get(CoCoAmdEpycAttestationRequestData.SNP_GUEST_REPORT_KEY));
        assertEquals(expectedVlekCertificate, requestDataCarlo2MapAlternative.get(CoCoAmdEpycAttestationRequestData.VLEK_CERTIFICATE_KEY));
        assertEquals(expectedSecureBootResult, requestDataCarlo2MapAlternative.get(CoCoSecureBootAttestationRequestData.SECURE_BOOT_ENABLED_KEY));

    }




    @Test
    public void countAttestationReportsForUserAndSystem() {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        mgr.createConfig(user, server3, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server3);

        TestUtils.flushSession();
        HibernateFactory.commitTransaction();
        TestUtils.clearSession();
        commitHappened();

        assertEquals(2, mgr.countCoCoAttestationReportsForUserAndServer(user, server));
        assertEquals(1, mgr.countCoCoAttestationReportsForUserAndServer(user, server3));

        assertThrows(PermissionException.class, () -> mgr.countCoCoAttestationReportsForUserAndServer(user, server2));
        assertThrows(PermissionException.class, () -> mgr.countCoCoAttestationReportsForUserAndServer(user2, server));
    }

    @Test
    public void testListReportsForUserAndSystem() {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server);

        TestUtils.flushSession();
        HibernateFactory.commitTransaction();
        TestUtils.clearSession();
        commitHappened();

        List<ServerCoCoAttestationReport> reports = mgr.listCoCoAttestationReportsForUserAndServer(user, server,
            new Date(0), 0, Integer.MAX_VALUE);
        assertEquals(2, reports.size());

        ServerCoCoAttestationReport latestReport = mgr.lookupLatestCoCoAttestationReport(user, server);
        assertEquals(CoCoAttestationStatus.SUCCEEDED, latestReport.getStatus());
        assertEquals("Some details", latestReport.getResults().get(0).getDetailsOpt().orElse(""));
    }

    @Test
    public void countAttestationReportsForUser() {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        mgr.createConfig(user, server3, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        mgr.createConfig(user2, server2, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        mgr.createConfig(user2, server4, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server3);

        createFakeAttestationReport(user2, server2);
        createFakeAttestationReport(user2, server2);
        createFakeAttestationReport(user2, server4);
        createFakeAttestationReport(user2, server4);
        createFakeAttestationReport(user2, server4);

        TestUtils.flushSession();
        HibernateFactory.commitTransaction();
        TestUtils.clearSession();
        commitHappened();

        assertEquals(3, mgr.countCoCoAttestationReportsForUser(user));
        assertEquals(5, mgr.countCoCoAttestationReportsForUser(user2));
    }

    @Test
    public void testListReportsForUser() {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        mgr.createConfig(user, server3, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        mgr.createConfig(user2, server2, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);
        mgr.createConfig(user2, server4, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server);
        createFakeAttestationReport(user, server3);

        createFakeAttestationReport(user2, server2);
        createFakeAttestationReport(user2, server2);
        createFakeAttestationReport(user2, server4);
        createFakeAttestationReport(user2, server4);
        createFakeAttestationReport(user2, server4);

        TestUtils.flushSession();
        HibernateFactory.commitTransaction();
        TestUtils.clearSession();
        commitHappened();

        List<ServerCoCoAttestationReport> reports = mgr.listCoCoAttestationReportsForUser(user, 0, Integer.MAX_VALUE);
        assertEquals(3, reports.size());
        assertTrue(reports.stream().allMatch(r -> List.of(server, server3).contains(r.getServer())));

        reports = mgr.listCoCoAttestationReportsForUser(user2, 0, Integer.MAX_VALUE);
        assertEquals(5, reports.size());
        assertTrue(reports.stream().allMatch(r -> List.of(server2, server4).contains(r.getServer())));
    }

    @Test
    public void testFilterListReports() throws InterruptedException {
        mgr.createConfig(user, server, CoCoEnvironmentType.KVM_AMD_EPYC_GENOA, true);

        long epochStart = (new Date().getTime() / 1000);
        for (int i = 10; i > 0; i--) {
            createFakeAttestationReport(user, server);
            TestUtils.flushSession();
            HibernateFactory.commitTransaction();
            commitHappened();
            TimeUnit.SECONDS.sleep(2);
        }
        TestUtils.clearSession();
        List<ServerCoCoAttestationReport> reports = mgr.listCoCoAttestationReportsForUserAndServer(user, server,
            new Date(0), 0, Integer.MAX_VALUE);
        assertEquals(10, reports.size());

        List<ServerCoCoAttestationReport> reports2 = mgr.listCoCoAttestationReportsForUserAndServer(user, server,
                new Date((epochStart + 10) * 1000L), 0, Integer.MAX_VALUE);
        assertTrue(reports2.get(0).getModified().compareTo(new Date((epochStart + 10) * 1000L)) >= 0);
        assertEquals(5, reports2.size());

        reports2 = mgr.listCoCoAttestationReportsForUserAndServer(user, server, new Date(0), 5, 2);
        assertEquals(2, reports2.size());
        assertEquals(reports.get(6), reports2.get(0));
        assertEquals(reports.get(7), reports2.get(1));
        assertTrue(reports2.get(0).getCreated().after(reports2.get(1).getCreated()),
                "Report 0 is not created after Report 1");
    }

    private void createFakeAttestationReport(User userIn, Server serverIn) {
        ServerCoCoAttestationReport report = mgr.initializeReport(userIn, serverIn);
        mgr.initializeResults(report);
        fakeSuccessfullAttestation(report);
    }
    private void fakeSuccessfullAttestation(ServerCoCoAttestationReport reportIn) {
        reportIn.getResults().forEach(res -> {
            res.setStatus(CoCoAttestationStatus.SUCCEEDED);
            res.setDetails("Some details");
            res.setAttested(new Date());
        });
    }

    private TaskomaticApi getTaskomaticApi() throws TaskomaticApiException {
        if (taskomaticApi == null) {
            taskomaticApi = context.mock(TaskomaticApi.class);
            context.checking(new Expectations() {
                {
                    allowing(taskomaticApi).scheduleActionExecution(with(any(Action.class)));
                }
            });
        }

        return taskomaticApi;
    }
}
