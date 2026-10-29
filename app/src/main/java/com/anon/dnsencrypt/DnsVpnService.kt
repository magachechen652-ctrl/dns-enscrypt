package com.anon.dnsencrypt

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Collections
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class DnsVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.anon.dnsencrypt.START"
        const val ACTION_STOP = "com.anon.dnsencrypt.STOP"
        const val EXTRA_RESOLVER = "resolver"
        const val CHANNEL_ID = "dns_vpn"
        const val NOTIF_ID = 1001

        @Volatile
        var isRunning = false

        @Volatile
        var currentResolver: Resolver = Resolver.ADGUARD

        val log: MutableList<String> = Collections.synchronizedList(ArrayList<String>())
    }

    private var tun: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val pool = Executors.newFixedThreadPool(4)
    private lateinit var resolver: DohResolver
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val res = intent.getStringExtra(EXTRA_RESOLVER)
                currentResolver = try {
                    Resolver.valueOf(res ?: "ADGUARD")
                } catch (e: Exception) {
                    Resolver.ADGUARD
                }
                startVpn()
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (running.get()) return

        resolver = DohResolver(currentResolver.dohUrl)

        val builder = Builder()
            .setSession("DNS Encrypt")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)
            .addDisallowedApplication(packageName)
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= 29) {
            builder.setMetered(false)
        }

        try {
            tun = builder.establish() ?: return
        } catch (e: Exception) {
            return
        }

        running.set(true)
        isRunning = true
        startForeground(NOTIF_ID, buildNotification())

        readerThread = Thread { readLoop() }.also { it.start() }
    }

    private fun readLoop() {
        val fd = tun?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        while (running.get()) {
            val length = try {
                input.read(buffer)
            } catch (e: Exception) {
                break
            }
            if (length <= 0) continue

            val packet = buffer.copyOf(length)
            val query = DnsPacket.parse(packet, length) ?: continue

            // UI log
            val domain = DnsPacket.extractDomain(query.dnsPayload)
            synchronized(log) {
                log.add("$domain → ${currentResolver.label}")
                if (log.size > 200) log.removeAt(0)
            }

            pool.execute {
                val answer = resolver.resolve(query.dnsPayload)
                val response = if (answer != null) {
                    DnsPacket.buildResponse(query, answer)
                } else {
                    DnsPacket.buildServFail(query)
                }
                synchronized(writeLock) {
                    try {
                        output.write(response)
                    } catch (e: Exception) {
                        // TUN closed — ignore
                    }
                }
            }
        }
    }

    private fun stopVpn() {
        running.set(false)
        isRunning = false
        readerThread?.interrupt()
        readerThread = null
        try {
            tun?.close()
        } catch (e: Exception) {
            // ignore
        }
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        pool.shutdownNow()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "DNS защита",
                NotificationManager.IMPORTANCE_LOW
            )
            nm?.createNotificationChannel(ch)
        }

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, DnsVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DNS шифруется")
            .setContentText("${currentResolver.label} · DoH")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(0, "Стоп", stopIntent)
            .build()
    }
}
