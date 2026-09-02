package com.example.ultravigilance

import com.example.ultravigilance.util.DetectedLink
import com.example.ultravigilance.util.LinkClassifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkClassifierTest {

    @Test
    fun testClassifyRawUpiScheme() {
        val text = "upi://pay?pa=merchant@okhdfcbank&pn=HDFC%20Store&am=1200&cu=INR"
        val result = LinkClassifier.classify(text)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Upi)
        val upi = result as DetectedLink.Upi
        assertEquals("merchant@okhdfcbank", upi.paymentData.pa)
        assertEquals("HDFC Store", upi.paymentData.pn)
        assertEquals("1200", upi.paymentData.am)
        assertEquals("SCHEME", upi.detectionSource)
    }

    @Test
    fun testClassifyEmbeddedUpiSchemeInSentence() {
        val sentence = "Hey, please pay using this link: upi://pay?pa=friend@okhdfcbank&pn=Friend&am=150.00 right now."
        val result = LinkClassifier.classify(sentence)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Upi)
        val upi = result as DetectedLink.Upi
        assertEquals("friend@okhdfcbank", upi.paymentData.pa)
        assertEquals("Friend", upi.paymentData.pn)
        assertEquals("150.00", upi.paymentData.am)
    }


    @Test
    fun testClassifyUpiVendorShortlinks() {
        val gpayUrl = "https://gpay.app.goo.gl/pay?pa=shopkeeper@okaxis&am=300"
        val result = LinkClassifier.classify(gpayUrl)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Upi)
        val upi = result as DetectedLink.Upi
        assertEquals("shopkeeper@okaxis", upi.paymentData.pa)
        assertEquals("VENDOR_LINK", upi.detectionSource)
    }

    @Test
    fun testClassifyVpaHandleInSentence() {
        val sentence = "Please send the registration fee to prize_winner@okaxis immediately."
        val result = LinkClassifier.classify(sentence)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Upi)
        val upi = result as DetectedLink.Upi
        assertEquals("prize_winner@okaxis", upi.paymentData.pa)
        assertEquals("VPA_HANDLE", upi.detectionSource)
    }

    @Test
    fun testClassifyGeneralWebLink() {
        val url = "https://secure-bank-login.com/auth"
        val result = LinkClassifier.classify(url)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Web)
        val web = result as DetectedLink.Web
        assertEquals("https://secure-bank-login.com/auth", web.url)
        assertEquals("secure-bank-login.com", web.host)
        assertEquals(false, web.isShortener)
    }

    @Test
    fun testClassifyShortenerLink() {
        val url = "https://bit.ly/kyc-verification-urgent"
        val result = LinkClassifier.classify(url)

        assertNotNull(result)
        assertTrue(result is DetectedLink.Web)
        val web = result as DetectedLink.Web
        assertEquals("bit.ly", web.host)
        assertTrue(web.isShortener)
    }

    @Test
    fun testClassifyNormalTextWithoutLink() {
        val text = "Hello, what time are we meeting today for dinner?"
        val result = LinkClassifier.classify(text)

        assertNull(result)
    }
}
