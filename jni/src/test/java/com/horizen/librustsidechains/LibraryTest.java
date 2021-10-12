package com.horizen.librustsidechains;

import org.junit.Test;
import static org.junit.Assert.*;

public class LibraryTest {

    @Test
    public void testLoad() {
        Library.load();
    }

    @Test(expected = NullPointerException.class)
    public void testExceptionOnNullPointer() {
        FieldElement fe = new FieldElement(0);
        fe.nativeSerializeFieldElement();
    }

    @Test(expected = NullPointerException.class)
    public void testIfMultipleExceptionsAlwaysFirstOneIsReturned() {
        FieldElement fe = new FieldElement(0);
        // Directly call native function otherwise we would immediately get an exception Java side.
        // This function first try to read the null pointer, causing a NullPointerException, then
        // tries to print the bytes, causing a panic that will be caught and converted into a
        // JavaRunTimeException. Assert that the function only returns the first exception.
        fe.nativePrintFieldElementBytes();
    }

    @Test(expected = RuntimeException.class)
    public void testPanicRustSideIsConvertedIntoRuntimeException() {
        Library.panickingFunction();
    }

    @Test
    public void testContinueExecutionAfterCatchingException() {
        // A crash happens Rust side resulting in a RuntimeException
        try {
            Library.panickingFunction();
            assertTrue(false); // Must never reach this point
        } catch (RuntimeException ex) {}

        // RuntimeException has been handled but JVM has not aborted, so
        // we can continue normally.
        FieldElement fe = FieldElement.createRandom();
        fe.freeFieldElement();
    }
}
