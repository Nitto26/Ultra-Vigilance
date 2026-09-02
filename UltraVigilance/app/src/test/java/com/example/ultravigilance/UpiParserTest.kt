package com.example.ultravigilance

import com.example.ultravigilance.util.UpiParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpiParserTest {

    @Test
    fun testIsUpiUri() {
        assertTrue(UpiParser.isUpiUri("upi://pay?pa=merchant@okaxis&pn=Merchant"))
        assertTrue(UpiParser.isUpiUri("UPI://PAY?PA=test@upi"))
        assertFalse(UpiParser.isUpiUri("https://google.com"))
        assertFalse(UpiParser.isUpiUri(null))
        assertFalse(UpiParser.isUpiUri(""))
        assertFalse(UpiParser.isUpiUri("mailto:test@example.com"))
    }

    @Test
    fun testParseStandardUpiUri() {
        val uri = "upi://pay?pa=shopkeeper@okaxis&pn=John%20Doe&am=500.00&cu=INR&tn=Grocery%20bill"
        val parsed = UpiParser.parse(uri)

        assertEquals(uri, parsed.rawUri)
        assertEquals("shopkeeper@okaxis", parsed.pa)
        assertEquals("John Doe", parsed.pn)
        assertEquals("500.00", parsed.am)
        assertEquals("INR", parsed.cu)
        assertEquals("Grocery bill", parsed.tn)
        assertEquals("John Doe", parsed.displayPayee)
        assertEquals("₹500.00", parsed.displayAmount)
    }

    @Test
    fun testParseMinimalUpiUri() {
        val uri = "upi://pay?pa=receiver@icici"
        val parsed = UpiParser.parse(uri)

        assertEquals("receiver@icici", parsed.pa)
        assertEquals("receiver@icici", parsed.displayPayee)
        assertEquals("Amount unspecified", parsed.displayAmount)
        assertEquals("INR", parsed.cu)
    }

    @Test
    fun testToScanRequest() {
        val uri = "upi://pay?pa=fraudster@upi&pn=Suspicious%20Seller&am=10000&tn=Lottery%20Fee"
        val parsed = UpiParser.parse(uri)
        val request = parsed.toScanRequest()

        assertEquals(uri, request.upiUri)
        assertEquals("fraudster@upi", request.pa)
        assertEquals("Suspicious Seller", request.pn)
        assertEquals("10000", request.am)
        assertEquals("INR", request.cu)
        assertEquals("Lottery Fee", request.tn)
    }
}
