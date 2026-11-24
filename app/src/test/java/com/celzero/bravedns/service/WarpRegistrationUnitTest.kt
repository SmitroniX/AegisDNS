/*
 * Copyright 2026 AegisDNS / RethinkDNS and its authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celzero.bravedns.service

import com.celzero.bravedns.wireguard.KeyPair
import com.celzero.bravedns.wireguard.WgInterface
import com.celzero.firestack.backend.WgKey
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config as RobolectricConfig

@RunWith(RobolectricTestRunner::class)
@RobolectricConfig(sdk = [28])
class WarpRegistrationUnitTest {

    @Test
    fun `parseWarpRegistrationJson extracts clientId, addresses, and direct ipv4 endpoint`() {
        val sampleJson =
            """
            {
              "id": "reg-abc-123",
              "token": "tok-xyz-789",
              "warp_enabled": false,
              "config": {
                "client_id": "r3oC",
                "interface": {
                  "addresses": {
                    "v4": "172.16.0.42",
                    "v6": "2606:4700:110:8f81::42"
                  }
                },
                "peers": [
                  {
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": {
                      "v4": "162.159.192.2:0",
                      "v6": "[2606:4700:d0::a29f:c002]:0",
                      "host": "engage.cloudflareclient.com:2408",
                      "ports": [2408, 500, 1701, 4500]
                    }
                  }
                ]
              }
            }
            """.trimIndent()

        val reg = WireguardManager.parseWarpRegistrationJson(sampleJson)
        assertNotNull(reg)
        requireNotNull(reg)
        assertEquals("reg-abc-123", reg.regId)
        assertEquals("tok-xyz-789", reg.token)
        assertEquals("r3oC", reg.clientId)
        assertEquals("172.16.0.42/32", reg.clientIpv4)
        assertEquals("2606:4700:110:8f81::42/128", reg.clientIpv6)
        assertEquals("162.159.192.2:2408", reg.endpoint)
    }

    @Test
    fun `parseWarpRegistrationJson rejects malformed or incomplete payloads`() {
        assertNull(WireguardManager.parseWarpRegistrationJson("not-json"))
        assertNull(WireguardManager.parseWarpRegistrationJson("{}"))
        assertNull(WireguardManager.parseWarpRegistrationJson("""{"id":"1","config":{"interface":{}}}"""))
    }

    @Test
    fun `buildWarpConfigString emits ClientID and WgInterface forwards client_id to firestack`() {
        val dummyPrivateKey = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        val reg =
            WireguardManager.WarpRegistration(
                regId = "id1",
                token = "tok1",
                clientIpv4 = "172.16.0.2/32",
                clientIpv6 = "2606:4700:110::2/128",
                peerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                endpoint = "162.159.192.2:2408",
                clientId = "r3oC"
            )

        val ini = WireguardManager.buildWarpConfigString(
            privateKey = dummyPrivateKey,
            registration = reg,
            dnsServers = "1.1.1.1, 94.140.15.15"
        )
        assertTrue(ini.contains("PrivateKey = $dummyPrivateKey"))
        assertTrue(ini.contains("Address = 172.16.0.2/32, 2606:4700:110::2/128"))
        assertTrue(ini.contains("DNS = 1.1.1.1, 94.140.15.15"))
        assertTrue(ini.contains("MTU = 1280"))
        assertTrue(ini.contains("ClientID = r3oC"))
        assertTrue(ini.contains("Endpoint = 162.159.192.2:2408"))

        // Verify WgInterface parses ClientID and emits client_id= for firestack's wgproxy.go
        val key = mockk<WgKey>()
        every { key.hex() } returns "aa".repeat(32)
        every { key.base64() } returns dummyPrivateKey
        val keyPair = mockk<KeyPair>()
        every { keyPair.getPrivateKey() } returns key
        every { keyPair.getPublicKey() } returns mockk()

        val wgIface = WgInterface.Builder()
            .setKeyPair(keyPair)
            .parseAddresses("172.16.0.2/32, 2606:4700:110::2/128")
            .parseDnsServers("1.1.1.1, 94.140.15.15")
            .parseMtu("1280")
            .parseClientId("r3oC")
            .build()

        assertEquals("r3oC", wgIface.getClientId().orElse(""))
        assertTrue(wgIface.toWgUserspaceString(skipListenPort = true).contains("client_id=r3oC\n"))
    }
}
