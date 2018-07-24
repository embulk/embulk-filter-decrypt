package org.embulk.filter.decrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.datatype.guava.GuavaModule;
import com.fasterxml.jackson.datatype.joda.JodaModule;
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
import org.embulk.spi.type.Types;
import org.embulk.test.TestingEmbulk;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.junit.Assume.assumeThat;
import static org.junit.internal.matchers.ThrowableCauseMatcher.hasCause;

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

    private class Control implements FilterPlugin.Control
    {
        @Override
        public void run(TaskSource taskSource, Schema outputSchema)
        {
            TestDecryptFilterPlugin.this.outputSchema = outputSchema;
            plugin.open(taskSource, inputSchema, outputSchema, output);
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

    private void execute(String name) throws IOException
    {
        plugin.transaction(config(name), inputSchema, new Control());
        ArrayNode jsonNodes = MockPageOutputReader.readPageOutput(outputSchema, (TestPageBuilderReader.MockPageOutput) output);
        Assert.assertNotNull(jsonNodes);
    }

    @Test
    public void testLackOfKeyHex() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'key_hex' is required but not set");
        execute("lack_of_key_hex");
    }

    @Test
    public void testLackOfColumnNames() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Field 'column_names' is required but not set");
        execute("lack_of_column_names");
    }

    @Test
    public void testLackOfIvHex() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Algorithm 'AES-256-CBC' requires initialization vector. Please generate one and set it to iv_hex option");
        execute("lack_of_iv_hex");
    }

    @Test
    public void testInvalidKeyHex() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("java.lang.IllegalArgumentException: com.google.common.io.BaseEncoding$DecodingException: Unrecognized character: X");
        execute("invalid_key_hex");
    }

    @Test
    public void testInvalidIvHex() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("java.lang.IllegalArgumentException: com.google.common.io.BaseEncoding$DecodingException: Unrecognized character: X");
        execute("invalid_iv_hex");
    }

    @Test
    public void testColumnNames() throws IOException
    {
        thrown.expectCause(hasCause(isA(ConfigException.class)));
        thrown.expectMessage("Column 'col1' is not found");
        execute("invalid_column_names");
    }
}
