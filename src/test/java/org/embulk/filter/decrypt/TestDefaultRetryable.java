package org.embulk.filter.decrypt;

import org.embulk.EmbulkTestRuntime;
import org.embulk.spi.util.RetryExecutor;
import org.embulk.spi.util.RetryExecutor.RetryGiveupException;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.Callable;

import static java.lang.String.format;
import static org.msgpack.core.Preconditions.checkArgument;

public class TestDefaultRetryable
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();  // require for DefaultRetryable's logger

    private static class Deny extends RuntimeException implements Callable
    {
        private int pastCalls = 0;
        private final int targetCalls;
        private Exception exception;

        Deny(int targetCalls)
        {
            super(format("Try harder! (Will pass after %d calls)", targetCalls));
            checkArgument(targetCalls >= 0);
            this.targetCalls = targetCalls;
        }

        static Deny until(int calls)
        {
            return new Deny(calls);
        }

        Deny with(Exception exception)
        {
            this.exception = exception;
            return this;
        }

        @Override
        public Object call() throws Exception
        {
            if (pastCalls < targetCalls) {
                pastCalls++;
                if (exception != null) {
                    throw exception;
                }
                else {
                    throw this;
                }
            }
            pastCalls++;
            return null;
        }
    }

    private static RetryExecutor retryExecutor()
    {
        return RetryExecutor.retryExecutor()
                .withInitialRetryWait(0)
                .withMaxRetryWait(0);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void guaranteeRetryAttemptsJustLikeRetryable() throws Exception
    {
        retryExecutor()
                .withRetryLimit(0)
                .run(new DefaultRetryable(Deny.until(0)));
        retryExecutor()
                .withRetryLimit(1)
                .run(new DefaultRetryable(Deny.until(1)));
        retryExecutor()
                .withRetryLimit(2)
                .run(new DefaultRetryable(Deny.until(1)));
        retryExecutor()
                .withRetryLimit(3)
                .run(new DefaultRetryable(Deny.until(2)));
    }

    @Test(expected = RetryGiveupException.class)
    @SuppressWarnings("unchecked")
    public void failAfterExceedingAttemptsJustLikeRetryable() throws Exception
    {
        retryExecutor()
                .withRetryLimit(3)
                .run(new DefaultRetryable(Deny.until(4)));
    }

    @Test(expected = Deny.class)
    @SuppressWarnings("unchecked")
    public void executeShouldUnwrapRetryGiveupException() throws Exception
    {
        new DefaultRetryable(Deny.until(4))
                .executeWith(retryExecutor().withRetryLimit(3));
    }

    @Test(expected = RuntimeException.class)
    @SuppressWarnings("unchecked")
    public void executeShouldUnwrapRetryGiveupExceptionButRewrapCheckedExceptionInARuntimeException()
    {
        new DefaultRetryable(Deny.until(4).with(new Exception("A checked exception")))
                .executeWith(retryExecutor().withRetryLimit(3));
    }

    @Test(expected = IOException.class)
    public void executeAndPropagateAsIsShouldLeaveOriginalExceptionUnwrapped() throws IOException
    {
        RetryExecutor retryExc = retryExecutor().withRetryLimit(3);
        // An explicit type parameter for operation return type is needed here,
        // Without one, javac (at least on 1.8) will fails to infer the X exception type parameter.
        new DefaultRetryable<Object>() {
            @Override
            public Object call() throws IOException
            {
                throw new IOException();
            }
        }.executeWithCheckedException(retryExc, IOException.class);
    }

    @Test(expected = IllegalStateException.class)
    public void executeWithoutAnImplementationShouldThrowAnIllegalStateException()
    {
        new DefaultRetryable().executeWith(retryExecutor());
    }
}
