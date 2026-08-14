package org.noticer.collector

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class CollectorService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var collectionJob: Job? = null
    private var collector: PolarCollector? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopCollection()
            ACTION_START -> startCollection(intent.getStringExtra(EXTRA_DEVICE_ID).orEmpty())
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        collectionJob?.cancel()
        collector?.close()
        scope.cancel()
        super.onDestroy()
    }

    private fun startCollection(deviceId: String) {
        if (collectionJob?.isActive == true) return
        updateStatus(PublicCollectorStatus.CONNECTING)
        collectionJob = scope.launch {
            try {
                val activeCollector = PolarCollector(
                    polar = PolarBleSdkAdapter(this@CollectorService),
                    bridge = WipingRustBridge(NativeRustSink()),
                    publishStatus = ::updateStatus,
                )
                collector = activeCollector
                activeCollector.collect(deviceId)
            } catch (_: Throwable) {
                updateStatus(PublicCollectorStatus.FAULT)
                stopSelf()
            }
        }
    }

    private fun stopCollection() {
        updateStatus(PublicCollectorStatus.COVER_REQUIRED)
        collectionJob?.cancel()
        stopSelf()
    }

    private fun updateStatus(status: PublicCollectorStatus) {
        getSharedPreferences(PUBLIC_PREFS, MODE_PRIVATE)
            .edit()
            .putString(PUBLIC_STATUS, status.name)
            .apply()
        startForeground(NOTIFICATION_ID, notification(status))
    }

    private fun notification(status: PublicCollectorStatus): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(status.publicLabel())
            .setOngoing(status == PublicCollectorStatus.ACTIVE)
            .build()

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.collector_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    companion object {
        const val ACTION_START = "org.noticer.collector.START"
        const val ACTION_STOP = "org.noticer.collector.STOP"
        const val EXTRA_DEVICE_ID = "device_id"
        const val PUBLIC_PREFS = "public_collector_status"
        const val PUBLIC_STATUS = "status"
        private const val CHANNEL_ID = "noticer-acquisition"
        private const val NOTIFICATION_ID = 1105
    }
}

fun PublicCollectorStatus.publicLabel(): String = when (this) {
    PublicCollectorStatus.IDLE -> "Idle"
    PublicCollectorStatus.CONNECTING -> "Connecting"
    PublicCollectorStatus.NEGOTIATING -> "Negotiating approved streams"
    PublicCollectorStatus.ACTIVE -> "Private acquisition active"
    PublicCollectorStatus.COVER_REQUIRED -> "Cover behavior active"
    PublicCollectorStatus.FAULT -> "Acquisition unavailable"
}

