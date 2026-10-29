package com.anon.dnsencrypt

data class DnsQuery(
    val rawPacket: ByteArray,
    val dnsPayload: ByteArray,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val ipHeaderLength: Int
)

object DnsPacket {

    /**
     * Parse an IPv4/UDP packet from the TUN interface.
     * Returns null for anything that is not a DNS query (UDP dst port 53).
     */
    fun parse(packet: ByteArray, length: Int): DnsQuery? {
        if (length < 28) return null // min IPv4 header (20) + UDP (8)

        val version = (packet[0].toInt() shr 4) and 0xF
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0xF) * 4
        if (ihl < 20 || length < ihl + 8) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // UDP only

        val totalLength = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        if (totalLength > length || totalLength < ihl + 8) return null

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)

        // Only DNS queries (outgoing to port 53)
        if (dstPort != 53) return null

        val udpLength = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
        if (udpLength < 8 || ihl + udpLength > totalLength) return null

        val dnsLength = udpLength - 8
        if (dnsLength <= 0) return null

        val dnsPayload = packet.copyOfRange(ihl + 8, ihl + 8 + dnsLength)

        return DnsQuery(
            rawPacket = packet.copyOfRange(0, totalLength),
            dnsPayload = dnsPayload,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLength = ihl
        )
    }

    /**
     * Build an IPv4/UDP response packet from the original query and a DNS answer.
     */
    fun buildResponse(query: DnsQuery, dnsAnswer: ByteArray): ByteArray {
        val ipHeader = ByteArray(query.ipHeaderLength)
        System.arraycopy(query.rawPacket, 0, ipHeader, 0, query.ipHeaderLength)

        // Swap source/destination IP
        System.arraycopy(query.dstIp, 0, ipHeader, 12, 4)
        System.arraycopy(query.srcIp, 0, ipHeader, 16, 4)

        val udpLength = 8 + dnsAnswer.size
        val totalLength = query.ipHeaderLength + udpLength
        ipHeader[2] = ((totalLength shr 8) and 0xFF).toByte()
        ipHeader[3] = (totalLength and 0xFF).toByte()

        // IP checksum
        ipHeader[10] = 0
        ipHeader[11] = 0
        val ipChecksum = checksum(ipHeader, 0, query.ipHeaderLength)
        ipHeader[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        ipHeader[11] = (ipChecksum and 0xFF).toByte()

        // UDP header with swapped ports
        val udpHeader = ByteArray(8)
        udpHeader[0] = ((query.dstPort shr 8) and 0xFF).toByte()
        udpHeader[1] = (query.dstPort and 0xFF).toByte()
        udpHeader[2] = ((query.srcPort shr 8) and 0xFF).toByte()
        udpHeader[3] = (query.srcPort and 0xFF).toByte()
        udpHeader[4] = ((udpLength shr 8) and 0xFF).toByte()
        udpHeader[5] = (udpLength and 0xFF).toByte()
        udpHeader[6] = 0
        udpHeader[7] = 0

        // Pseudo-header for UDP checksum
        val pseudo = ByteArray(12)
        System.arraycopy(query.dstIp, 0, pseudo, 0, 4) // source = original dst
        System.arraycopy(query.srcIp, 0, pseudo, 4, 4) // destination = original src
        pseudo[8] = 0
        pseudo[9] = 17 // UDP
        pseudo[10] = ((udpLength shr 8) and 0xFF).toByte()
        pseudo[11] = (udpLength and 0xFF).toByte()

        val checksumData = ByteArray(12 + udpLength)
        System.arraycopy(pseudo, 0, checksumData, 0, 12)
        System.arraycopy(udpHeader, 0, checksumData, 12, 8)
        System.arraycopy(dnsAnswer, 0, checksumData, 20, dnsAnswer.size)

        val udpChecksum = checksum(checksumData, 0, checksumData.size)
        udpHeader[6] = ((udpChecksum shr 8) and 0xFF).toByte()
        udpHeader[7] = (udpChecksum and 0xFF).toByte()

        val out = ByteArray(totalLength)
        System.arraycopy(ipHeader, 0, out, 0, query.ipHeaderLength)
        System.arraycopy(udpHeader, 0, out, query.ipHeaderLength, 8)
        System.arraycopy(dnsAnswer, 0, out, query.ipHeaderLength + 8, dnsAnswer.size)
        return out
    }

    /**
     * Build a DNS SERVFAIL response so the app fails fast instead of leaking plaintext DNS.
     */
    fun buildServFail(query: DnsQuery): ByteArray {
        val q = query.dnsPayload.copyOf()
        if (q.size >= 12) {
            q[2] = (q[2].toInt() or 0x80).toByte() // QR = 1
            q[3] = ((q[3].toInt() and 0xF0) or 0x02).toByte() // RCODE = SERVFAIL
            q[6] = 0; q[7] = 0  // ANCOUNT
            q[8] = 0; q[9] = 0  // NSCOUNT
            q[10] = 0; q[11] = 0 // ARCOUNT
        }
        return buildResponse(query, q)
    }

    /**
     * Extract the first QNAME from a DNS query payload (for the UI log).
     */
    fun extractDomain(dns: ByteArray): String {
        if (dns.size < 12) return "?"
        var i = 12
        val sb = StringBuilder()
        while (i < dns.size) {
            val len = dns[i].toInt() and 0xFF
            if (len == 0) break
            if (len > 63 || i + 1 + len > dns.size) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(dns, i + 1, len))
            i += 1 + len
        }
        return sb.toString().ifEmpty { "?" }
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }
}
