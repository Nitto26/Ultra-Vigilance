package com.example.ultravigilance.data.network

import android.util.Log
import com.example.ultravigilance.data.model.ScanDocumentRequest
import com.example.ultravigilance.data.model.ScanDocumentResponse
import com.example.ultravigilance.data.model.ScanPaymentRequest
import com.example.ultravigilance.data.model.ScanSmsRequest
import com.example.ultravigilance.data.model.ScanVerdict
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

interface ScanApiService {
    @POST("scan-document")
    suspend fun scanDocument(@Body request: ScanDocumentRequest): Response<ScanDocumentResponse>

    @POST("scan-sms")
    suspend fun scanSms(@Body request: ScanSmsRequest): Response<ScanVerdict>

    @POST("scan-payment")
    suspend fun scanPayment(@Body request: ScanPaymentRequest): Response<ScanVerdict>
}

object ScanApiClient {
    private const val TAG = "ScanApiClient"

    // Active FastAPI backend tunnel hosting /scan-payment, /scan-document, and /scan-sms
    private const val BASE_URL = "https://mugwumpian-scottie-homely.ngrok-free.dev/"

    private val okHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            val request = chain.request().newBuilder()
                .addHeader("ngrok-skip-browser-warning", "true")
                .addHeader("User-Agent", "UltraVigilance-Android")
                .build()

            Log.d(TAG, "🚀 HTTP ${request.method} -> ${request.url}")
            val response = chain.proceed(request)
            Log.d(TAG, "📥 HTTP ${response.code} <- ${request.url}")
            response
        }
        .build()

    val api: ScanApiService by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ScanApiService::class.java)
    }
}
