package org.embulk.filter.decrypt;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.Region;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import org.apache.http.HttpStatus;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigLoader;
import org.embulk.config.ConfigSource;
import org.embulk.config.ModelManager;
import org.embulk.config.TaskSource;
import org.embulk.spi.FilterPlugin;
import org.embulk.spi.PageOutput;
import org.embulk.spi.Schema;
import org.embulk.spi.TestPageBuilderReader;
import org.embulk.spi.time.Timestamp;
import org.embulk.spi.type.Types;
import org.embulk.spi.util.RetryExecutor;
import org.embulk.test.TestingEmbulk;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.embulk.spi.PageTestUtils.buildPage;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeThat;
import static org.junit.internal.matchers.ThrowableCauseMatcher.hasCause;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class TestDecryptFilterPlugin
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    @Rule
    public TestingEmbulk embulk = TestingEmbulk.builder()
            .registerPlugin(FilterPlugin.class, "decrypt", DecryptFilterPlugin.class)
            .build();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private DecryptFilterPlugin plugin;

    private Schema inputSchema;

    private Schema outputSchema;

    private PageOutput output;

    private PageOutput resultOutput;

    private AmazonS3 client;

    private class Control implements FilterPlugin.Control
    {
        @Override
        public void run(TaskSource taskSource, Schema outputSchema)
        {
            TestDecryptFilterPlugin.this.outputSchema = outputSchema;
            TestDecryptFilterPlugin.this.resultOutput = plugin.open(taskSource, inputSchema, outputSchema, output);
        }
    }

    @Before
    public void setup()
    {
        plugin = new DecryptFilterPlugin();
        inputSchema = Schema.builder()
                .add("should_be_decrypted", Types.STRING)
                .build();
        output = new TestPageBuilderReader.MockPageOutput();
        client = mock(AmazonS3.class);
    }

    @After
    public void tearDown()
    {
        output.finish();
        output.close();
    }

    /**
     * Load plugin config with Guava & Joda support
     */
    ConfigSource config(String name)
    {
        String path = System.getenv("EMBULK_FILTER_DECRYPT_TEST_CONFIG");
        assumeThat(isNullOrEmpty(path), is(false));

        try {
            ObjectMapper mapper = new ObjectMapper()
                    .registerModule(new GuavaModule())
                    .registerModule(new JodaModule());
            ConfigLoader configLoader = new ConfigLoader(new ModelManager(null, mapper));
            return configLoader.fromYamlFile(new File(path)).getNested(name);
        }
        catch (IOException e) {
            throw new RuntimeException();
        }
    }

    private void execute(String name)
    {
        plugin.transaction(config(name), inputSchema, new Control());
    }

    private ArrayNode decrypt(Object... values) throws IOException
    {
        resultOutput.add(buildPage(runtime.getBufferAllocator(), inputSchema, values).get(0));
        resultOutput.finish();
        resultOutput.close();
        return MockPageOutputReader.readPageOutput(outputSchema, (TestPageBuilderReader.MockPageOutput) output);
    }

    @Test
    public void testLackOfKeyHex()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'key_hex' is required but not set");
        execute("lack_of_key_hex");
    }

    @Test
    public void testLackOfColumnNames()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'column_names' is required but not set");
        execute("lack_of_column_names");
    }

    @Test
    public void testLackOfIvHex()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Algorithm 'AES-256-CBC' requires initialization vector. Please generate one and set it to iv_hex option");
        execute("lack_of_iv_hex");
    }

    @Test
    public void testNonIvAlgorithmShouldBeSilentEvenLackOfIvHex()
    {
        execute("algorithm_not_require_iv");
    }

    @Test
    public void testInvalidKeyHex()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("java.lang.IllegalArgumentException: com.google.common.io.BaseEncoding$DecodingException: Unrecognized character: X");
        execute("invalid_key_hex");
    }

    @Test
    public void testInvalidIvHex()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("java.lang.IllegalArgumentException: com.google.common.io.BaseEncoding$DecodingException: Unrecognized character: X");
        execute("invalid_iv_hex");
    }

    @Test
    public void testInvalidColumnNames()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Column 'col1' is not found");
        execute("invalid_column_names");
    }

    @Test
    public void testUnsupportedAlgorithm()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Unsupported algorithm 'ABC'. Supported algorithms are AES-256-CBC, AES-192-CBC, AES-128-CBC, AES-256-ECB, AES-192-ECB, AES-128-ECB");
        execute("unsupported_algorithm");
    }

    @Test
    public void testUnsupportedOutputEncoding()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Unsupported output encoding 'abc'. Supported encodings are base64, hex");
        execute("unsupported_output_encoding");
    }

    @Test
    public void testDefaultOutputEncodingShouldBeBase64()
    {
        DecryptFilterPlugin.PluginTask task = config("default_output_encoding").loadConfig(DecryptFilterPlugin.PluginTask.class);
        assertEquals(task.getOutputEncoding(), DecryptFilterPlugin.Encoder.BASE64);
    }

    @Test
    public void testDecryptAES_256_CBCAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-256-CBC_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_256_CBCAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-256-CBC_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("814CF30BE9C94812DB3D30332656DB30");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_256AlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-256_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_256AlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-256_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("814CF30BE9C94812DB3D30332656DB30");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAESAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAESAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("814CF30BE9C94812DB3D30332656DB30");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192_CBCAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-192-CBC_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192_CBCAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-192-CBC_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("814CF30BE9C94812DB3D30332656DB30");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192AlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-192_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192AlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-192_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("814CF30BE9C94812DB3D30332656DB30");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_256_ECBAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-256-ECB_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("CO5cH3pGbD4TbUVp9KiOjA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_256_ECBAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-256-ECB_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("08EE5C1F7A466C3E136D4569F4A88E8C");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192_ECBAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-192-ECB_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("CO5cH3pGbD4TbUVp9KiOjA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_192_ECBAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-192-ECB_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("08EE5C1F7A466C3E136D4569F4A88E8C");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_128_ECBAlgorithmBase64OutputEncoding() throws IOException
    {
        execute("algorithm_AES-128-ECB_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("CO5cH3pGbD4TbUVp9KiOjA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testDecryptAES_128_ECBAlgorithmHexOutputEncoding() throws IOException
    {
        execute("algorithm_AES-128-ECB_output_encoding_Hex");
        ArrayNode arrayNode = decrypt("08EE5C1F7A466C3E136D4569F4A88E8C");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testOnlyDecryptTargetColumn() throws IOException
    {
        inputSchema = Schema.builder()
                .add("should_be_decrypted", Types.STRING)
                .add("should_be_not_decrypted", Types.STRING)
                .build();
        execute("algorithm_AES-256-CBC_output_encoding_Base64");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==", "don't decrypt me");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());

        assertNotNull(arrayNode.get(0).get("should_be_not_decrypted"));
        assertEquals("Column should be not decrypted", "don't decrypt me", arrayNode.get(0).get("should_be_not_decrypted").asText());
    }

    @Test
    public void testBooleanColumnShouldBeNotDecrypted() throws IOException
    {
        inputSchema = Schema.builder()
                .add("should_be_not_decrypted", Types.BOOLEAN)
                .build();
        execute("shoud_be_not_decrypted");
        ArrayNode arrayNode = decrypt(true);
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_not_decrypted"));
        assertEquals("Column should be not decrypted", true, arrayNode.get(0).get("should_be_not_decrypted").asBoolean());
    }

    @Test
    public void testLongColumnShouldBeNotDecrypted() throws IOException
    {
        inputSchema = Schema.builder()
                .add("should_be_not_decrypted", Types.LONG)
                .build();
        execute("shoud_be_not_decrypted");
        ArrayNode arrayNode = decrypt(1L);
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_not_decrypted"));
        assertEquals("Column should be not decrypted", 1L, arrayNode.get(0).get("should_be_not_decrypted").asLong());
    }

    @Test
    public void testDoubleColumnShouldBeNotDecrypted() throws IOException
    {
        inputSchema = Schema.builder()
                .add("should_be_not_decrypted", Types.DOUBLE)
                .build();
        execute("shoud_be_not_decrypted");
        ArrayNode arrayNode = decrypt(1.1d);
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_not_decrypted"));
        assertEquals(1.1d, arrayNode.get(0).get("should_be_not_decrypted").asDouble(), 0);
    }

    @Test
    public void testTimestampColumnShouldBeNotDecrypted() throws IOException
    {
        inputSchema = Schema.builder()
                .add("should_be_not_decrypted", Types.TIMESTAMP)
                .build();
        execute("shoud_be_not_decrypted");
        Date now = new Date();
        ArrayNode arrayNode = decrypt(Timestamp.ofEpochMilli(now.getTime()));
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_not_decrypted"));
        assertEquals("Column should be not decrypted", String.valueOf(now.getTime()), arrayNode.get(0).get("should_be_not_decrypted").asText());
    }

    @Test
    public void testS3ForAlgorithmRequiredIV() throws IOException
    {
        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05");
        keys.put("iv_hex", "C9DD4BB33B827EB1FBA1B16A0074D460");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class), any(RetryExecutor.class));
        execute("s3_with_algorithm_required_iv");
        ArrayNode arrayNode = decrypt("gUzzC+nJSBLbPTAzJlbbMA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testS3WithoutIVForAlgorithmNotRequiredIV() throws IOException
    {
        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class), any(RetryExecutor.class));
        execute("s3_with_algorithm_not_required_iv");
        ArrayNode arrayNode = decrypt("CO5cH3pGbD4TbUVp9KiOjA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testS3WithIVForAlgorithmNotRequiredIV() throws IOException
    {
        plugin = spy(plugin);
        Map<String, String> keys = new HashMap<>();
        keys.put("key_hex", "098F6BCD4621D373CADE4E832627B4F60A9172716AE6428409885B8B829CCB05");
        keys.put("iv_hex", "C9DD4BB33B827EB1FBA1B16A0074D460");
        doReturn(keys).when(plugin).retrieveKey(any(String.class), any(String.class), any(AmazonS3.class), any(RetryExecutor.class));
        execute("s3_with_algorithm_not_required_iv");
        ArrayNode arrayNode = decrypt("CO5cH3pGbD4TbUVp9KiOjA==");
        assertEquals(arrayNode.size(), 1);
        assertNotNull(arrayNode.get(0));
        assertNotNull(arrayNode.get(0).get("should_be_decrypted"));
        String expected = "secret";
        assertEquals("Column should be decrypted", expected, arrayNode.get(0).get("should_be_decrypted").asText());
    }

    @Test
    public void testS3ConfiguredRegion()
    {
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        AmazonS3 s3Client = plugin.newS3Client(configSource.loadConfig(DecryptFilterPlugin.PluginTask.class).getAWSParams().get());

        // Should reflect the region configuration as is
        assertEquals(s3Client.getRegion(), Region.US_East_2);
    }

    @Test
    public void testS3WithInvalidRegion()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        execute("s3_with_invalid_region");
    }

    @Test
    public void testS3LackOfAWSParams()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("AWS Params are required for S3 Key type");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.remove("aws_params");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    @Test
    public void testS3LackOfAWSParamsRegion()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'region' is required but not set");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.getNested("aws_params").remove("region");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    @Test
    public void testS3LackOfAWSParamsAccessKey()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'access_key' is required but not set");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.getNested("aws_params").remove("access_key");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    @Test
    public void testS3LackOfAWSParamsSecretKey()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'secret_key' is required but not set");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.getNested("aws_params").remove("secret_key");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    @Test
    public void testS3LackOfAWSParamsBucket()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'bucket' is required but not set");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.getNested("aws_params").remove("bucket");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    @Test
    public void testS3LackOfAWSParamsFullPath()
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'full_path' is required but not set");
        ConfigSource configSource = config("s3_with_algorithm_required_iv");
        configSource.getNested("aws_params").remove("full_path");
        plugin.transaction(configSource, inputSchema, new Control());
    }

    private static RetryExecutor retryExecutor()
    {
        return RetryExecutor.retryExecutor()
                .withInitialRetryWait(0)
                .withMaxRetryWait(0);
    }

    @Test
    public void testS3OnRetryGiveUpShouldThrowConfigExceptionForExceptionInForbiddenCode() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        AmazonServiceException exception = new AmazonServiceException("Forbidden exception");
        exception.setStatusCode(HttpStatus.SC_FORBIDDEN);
        exception.setErrorType(AmazonServiceException.ErrorType.Client);
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3OnRetryGiveUpShouldThrowConfigExceptionForExceptionInMethodNotAllowCode() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        AmazonServiceException exception = new AmazonServiceException("method not allow exception");
        exception.setStatusCode(HttpStatus.SC_METHOD_NOT_ALLOWED);
        exception.setErrorType(AmazonServiceException.ErrorType.Client);
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3OnRetryGiveUpShouldThrowConfigExceptionForExceptionExpiredTokenCode() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        AmazonServiceException exception = new AmazonServiceException("expired token exception");
        exception.setStatusCode(HttpStatus.SC_BAD_REQUEST);
        exception.setErrorCode("ExpiredToken");
        exception.setErrorType(AmazonServiceException.ErrorType.Client);
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3OnRetryGiveUpShouldThrowConfigExceptionForExceptionNoSuchBucketCode() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        AmazonServiceException exception = new AmazonServiceException("no such bucket exception");
        exception.setErrorCode("NoSuchBucket");
        exception.setErrorType(AmazonServiceException.ErrorType.Client);
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3OnRetryGiveUpShouldThrowConfigExceptionForExceptionNoSuchKeyCode() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        AmazonServiceException exception = new AmazonServiceException("no such key exception");
        exception.setErrorCode("NoSuchKey");
        exception.setErrorType(AmazonServiceException.ErrorType.Client);
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3RetryableExceptionShouldThrowOriginalException() throws IOException
    {
        thrown.expectCause(hasCause(isA(AmazonServiceException.class)));
        AmazonServiceException exception = new AmazonServiceException("retryable exception");
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }

    @Test
    public void testS3SdkClientExceptionShouldThrowOriginalException() throws IOException
    {
        thrown.expectCause(hasCause(isA(SdkClientException.class)));
        SdkClientException exception = new SdkClientException("sdk client exception");
        doThrow(exception).when(client).getObject(any(GetObjectRequest.class));
        plugin.retrieveKey("a_bucket", "a_path", client, retryExecutor().withRetryLimit(1));
    }
}
