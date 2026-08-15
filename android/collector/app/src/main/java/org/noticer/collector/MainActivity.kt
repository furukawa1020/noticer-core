package org.noticer.collector

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var statusView: TextView
    private lateinit var deviceIdView: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildContent())
        requestCollectorPermissions()
    }

    override fun onResume() {
        super.onResume()
        val stored = getSharedPreferences(CollectorService.PUBLIC_PREFS, MODE_PRIVATE)
            .getString(CollectorService.PUBLIC_STATUS, PublicCollectorStatus.IDLE.name)
        val status = runCatching { PublicCollectorStatus.valueOf(stored.orEmpty()) }
            .getOrDefault(PublicCollectorStatus.IDLE)
        statusView.text = status.publicLabel()
    }

    private fun buildContent(): LinearLayout {
        val padding = (24 * resources.displayMetrics.density).toInt()
        statusView = TextView(this).apply {
            text = PublicCollectorStatus.IDLE.publicLabel()
            textSize = 24f
            setTextColor(Color.rgb(19, 62, 54))
        }
        deviceIdView = EditText(this).apply {
            hint = "Polar device ID"
            contentDescription = "Polar device ID"
            maxLines = 1
        }
        val start = Button(this).apply {
            text = "Start private acquisition"
            setOnClickListener {
                val intent = Intent(this@MainActivity, CollectorService::class.java)
                    .setAction(CollectorService.ACTION_START)
                    .putExtra(CollectorService.EXTRA_DEVICE_ID, deviceIdView.text.toString().trim())
                startForegroundService(intent)
                deviceIdView.text.clear()
                statusView.text = PublicCollectorStatus.CONNECTING.publicLabel()
            }
        }
        val stop = Button(this).apply {
            text = "Stop"
            setOnClickListener {
                startService(
                    Intent(this@MainActivity, CollectorService::class.java)
                        .setAction(CollectorService.ACTION_STOP),
                )
                statusView.text = PublicCollectorStatus.COVER_REQUIRED.publicLabel()
            }
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(padding, padding, padding, padding)
            setBackgroundColor(Color.rgb(244, 240, 230))
            addView(statusView)
            addView(deviceIdView)
            addView(start)
            addView(stop)
        }
    }

    private fun requestCollectorPermissions() {
        val permissions = listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.POST_NOTIFICATIONS,
        ).filter { permission -> checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED }
        if (permissions.isNotEmpty()) {
            requestPermissions(permissions.toTypedArray(), 1105)
        }
    }
}

