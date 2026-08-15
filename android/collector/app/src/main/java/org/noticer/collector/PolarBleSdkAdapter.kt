package org.noticer.collector

import android.content.Context
import com.polar.sdk.api.PolarBleApi
import com.polar.sdk.api.PolarBleApiDefaultImpl
import com.polar.sdk.api.model.PolarSensorSetting
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

interface PolarSdkPort {
    suspend fun connect(deviceId: String)
    suspend fun requestSettings(deviceId: String, kind: StreamKind): AvailableSettings
    fun ppg(deviceId: String, settings: SelectedSettings): Flow<PpgBatch>
    fun acc(deviceId: String, settings: SelectedSettings): Flow<AccBatch>
    suspend fun stop(deviceId: String, kind: StreamKind)
    suspend fun disconnect(deviceId: String)
    fun close()
}

class PolarBleSdkAdapter(context: Context) : PolarSdkPort {
    private val api = PolarBleApiDefaultImpl.defaultImplementation(
        context.applicationContext,
        setOf(PolarBleApi.PolarBleSdkFeature.FEATURE_POLAR_ONLINE_STREAMING),
    )

    override suspend fun connect(deviceId: String) {
        api.connectToDevice(deviceId)
    }

    override suspend fun requestSettings(deviceId: String, kind: StreamKind): AvailableSettings {
        val settings = api.requestStreamSettings(deviceId, kind.toPolarType())
        return AvailableSettings(
            settings.settings.mapKeys { (key, _) -> key.toDomainKey() },
        )
    }

    override fun ppg(deviceId: String, settings: SelectedSettings): Flow<PpgBatch> =
        api.startPpgStreaming(deviceId, settings.toPolarSettings()).map { data ->
            BatchConverter.ppg(
                data.samples.map { sample ->
                    RawPpgSample(sample.timeStamp, sample.channelSamples)
                },
                settings.sampleRateHz,
            )
        }

    override fun acc(deviceId: String, settings: SelectedSettings): Flow<AccBatch> =
        api.startAccStreaming(deviceId, settings.toPolarSettings()).map { data ->
            BatchConverter.acc(
                data.samples.map { sample ->
                    RawAccSample(sample.timeStamp, sample.x, sample.y, sample.z)
                },
                settings.sampleRateHz,
            )
        }

    override suspend fun stop(deviceId: String, kind: StreamKind) = Unit

    override suspend fun disconnect(deviceId: String) {
        api.disconnectFromDevice(deviceId)
    }

    override fun close() = api.shutDown()

    private fun StreamKind.toPolarType(): PolarBleApi.PolarDeviceDataType = when (this) {
        StreamKind.PPG -> PolarBleApi.PolarDeviceDataType.PPG
        StreamKind.ACC -> PolarBleApi.PolarDeviceDataType.ACC
    }

    private fun PolarSensorSetting.SettingType.toDomainKey(): SettingKey = when (this) {
        PolarSensorSetting.SettingType.SAMPLE_RATE -> SettingKey.SAMPLE_RATE
        PolarSensorSetting.SettingType.RESOLUTION -> SettingKey.RESOLUTION
        PolarSensorSetting.SettingType.RANGE -> SettingKey.RANGE
        PolarSensorSetting.SettingType.CHANNELS -> SettingKey.CHANNELS
    }

    private fun SelectedSettings.toPolarSettings(): PolarSensorSetting = PolarSensorSetting(
        values.mapKeys { (key, _) ->
            when (key) {
                SettingKey.SAMPLE_RATE -> PolarSensorSetting.SettingType.SAMPLE_RATE
                SettingKey.RESOLUTION -> PolarSensorSetting.SettingType.RESOLUTION
                SettingKey.RANGE -> PolarSensorSetting.SettingType.RANGE
                SettingKey.CHANNELS -> PolarSensorSetting.SettingType.CHANNELS
            }
        },
    )
}
