package com.anon.dnsencrypt

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var status: TextView
    private lateinit var button: Button
    private lateinit var spinner: Spinner
    private lateinit var logView: TextView

    private val handler = Handler(Looper.getMainLooper())

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpn()
    }

    private val logRunnable = object : Runnable {
        override fun run() {
            val lines = synchronized(DnsVpnService.log) {
                DnsVpnService.log.takeLast(20).toList()
            }
            logView.text = lines.joinToString("\n")
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        button = findViewById(R.id.toggle)
        spinner = findViewById(R.id.resolver)
        logView = findViewById(R.id.log)

        val labels = Resolver.values().map { it.label }
        spinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            labels
        )

        button.setOnClickListener {
            if (DnsVpnService.isRunning) stopVpn() else requestAndStart()
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }

        updateUi()
    }

    private fun requestAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermission.launch(intent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val selected = Resolver.values()[spinner.selectedItemPosition]
        val i = Intent(this, DnsVpnService::class.java)
            .setAction(DnsVpnService.ACTION_START)
            .putExtra(DnsVpnService.EXTRA_RESOLVER, selected.name)
        startForegroundService(i)
        status.postDelayed({ updateUi() }, 300)
    }

    private fun stopVpn() {
        val i = Intent(this, DnsVpnService::class.java)
            .setAction(DnsVpnService.ACTION_STOP)
        startService(i)
        status.postDelayed({ updateUi() }, 300)
    }

    private fun updateUi() {
        if (DnsVpnService.isRunning) {
            status.text = "Защита включена · ${DnsVpnService.currentResolver.label}"
            button.text = "Расшифровать"
        } else {
            status.text = "Защита выключена"
            button.text = "Шифровать"
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(logRunnable)
        updateUi()
    }

    override fun onPause() {
        handler.removeCallbacks(logRunnable)
        super.onPause()
    }
}
