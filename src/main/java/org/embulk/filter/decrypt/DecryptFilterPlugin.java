package org.embulk.filter.decrypt;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.base.Optional;
import com.google.common.io.BaseEncoding;
import org.embulk.config.Config;
import org.embulk.config.ConfigDefault;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.Task;
import org.embulk.config.TaskSource;
import org.embulk.spi.Exec;
import org.embulk.spi.FilterPlugin;
import org.embulk.spi.PageOutput;
import org.embulk.spi.Schema;
import org.slf4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.List;

import static java.lang.String.format;
import static org.apache.commons.lang3.StringUtils.join;

public class DecryptFilterPlugin
        implements FilterPlugin
{
    public enum Algorithm
    {
        AES_256_CBC("AES/CBC/PKCS5Padding", "AES", 256, true, "AES", "AES-256", "AES-256-CBC"),
        AES_192_CBC("AES/CBC/PKCS5Padding", "AES", 192, true, "AES-192", "AES-192-CBC"),
        AES_128_CBC("AES/CBC/PKCS5Padding", "AES", 128, true, "AES-128", "AES-128-CBC"),
        AES_256_ECB("AES/ECB/PKCS5Padding", "AES", 256, false, "AES-256-ECB"),
        AES_192_ECB("AES/ECB/PKCS5Padding", "AES", 192, false, "AES-192-ECB"),
        AES_128_ECB("AES/ECB/PKCS5Padding", "AES", 128, false, "AES-128-ECB");

        private final String javaName;
        private final String javaKeySpecName;
        private final int keyLength;
        private final boolean useIv;
        private String[] displayNames;

        Algorithm(String javaName, String javaKeySpecName, int keyLength, boolean useIv, String... displayNames)
        {
            this.javaName = javaName;
            this.javaKeySpecName = javaKeySpecName;
            this.keyLength = keyLength;
            this.useIv = useIv;
            this.displayNames = displayNames;
        }

        public String getJavaName()
        {
            return javaName;
        }

        public String getJavaKeySpecName()
        {
            return javaKeySpecName;
        }

        public int getKeyLength()
        {
            return keyLength;
        }

        public boolean useIv()
        {
            return useIv;
        }

        @JsonCreator
        public static Algorithm fromName(String name)
        {
            for (Algorithm algo : EnumSet.allOf(Algorithm.class)) {
                for (String n : algo.displayNames) {
                    if (n.equals(name)) {
                        return algo;
                    }
                }
            }
            throw new ConfigException("Unsupported algorithm '" + name + "'. Supported algorithms are AES-256-CBC, AES-192-CBC, AES-128-CBC.");
        }

        @JsonValue
        @Override
        public String toString()
        {
            return displayNames[displayNames.length - 1];
        }
    }

    public enum Encoder
    {
        BASE64("base64", BaseEncoding.base64()),
        HEX("hex", BaseEncoding.base16());

        private final BaseEncoding encoding;
        private final String name;

        Encoder(String name, BaseEncoding encoding)
        {
            this.name = name;
            this.encoding = encoding;
        }

        public String encode(byte[] bytes)
        {
            return encoding.encode(bytes);
        }

        @JsonCreator
        public static Encoder fromName(String name)
        {
            EnumSet<Encoder> encoders = EnumSet.allOf(Encoder.class);
            for (Encoder encoder : encoders) {
                if (encoder.name.equals(name)) {
                    return encoder;
                }
            }
            throw new ConfigException(
                    format("Unsupported output encoding '%s'. Supported encodings are %s.",
                            name,
                            join(encoders, ", ")));
        }

        @JsonValue
        @Override
        public String toString()
        {
            return name;
        }
    }

    public interface PluginTask
            extends Task
    {
        @Config("algorithm")
        public Algorithm getAlgorithm();

        @Config("output_encoding")
        @ConfigDefault("\"base64\"")
        public Encoder getOutputEncoding();

        @Config("key_hex")
        public String getKeyHex();

        @Config("iv_hex")
        @ConfigDefault("null")
        public Optional<String> getIvHex();

        @Config("column_names")
        public List<String> getColumnNames();
    }

    private static final Logger log = Exec.getLogger(DecryptFilterPlugin.class);

    @Override
    public void transaction(ConfigSource config, Schema inputSchema,
            FilterPlugin.Control control)
    {
        PluginTask task = config.loadConfig(PluginTask.class);

        validate(task, inputSchema);

        control.run(task.dump(), inputSchema);
    }

    @Override
    public PageOutput open(TaskSource taskSource, Schema inputSchema,
            Schema outputSchema, PageOutput output)
    {
        PluginTask task = taskSource.loadTask(PluginTask.class);

        // Write your code here :)
        throw new UnsupportedOperationException("DecryptFilterPlugin.open method is not implemented yet");
    }

    private void validate(PluginTask task, Schema schema) throws ConfigException
    {
        if (task.getAlgorithm().useIv() && !task.getIvHex().isPresent()) {
            throw new ConfigException("Algorithm '" + task.getAlgorithm() + "' requires initialization vector. Please generate one and set it to iv_hex option.");
        }
        else if (!task.getAlgorithm().useIv() && task.getIvHex().isPresent()) {
            log.warn("Algorithm '" + task.getAlgorithm() + "' doesn't use initialization vector. iv_hex is ignore");
        }

        // Validate Cipher
        try {
            getCipher(Cipher.DECRYPT_MODE, task);
        }
        catch (Exception e) {
            throw new ConfigException(e);
        }

        // validate column_names
        for (String name : task.getColumnNames()) {
            schema.lookupColumn(name);
        }
    }

    private Cipher getCipher(int mode, PluginTask task)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException
    {
        Algorithm algo = task.getAlgorithm();

        byte[] keyData = BaseEncoding.base16().decode(task.getKeyHex());
        SecretKeySpec key = new SecretKeySpec(keyData, algo.getJavaKeySpecName());

        if (algo.useIv()) {
            byte[] ivData = BaseEncoding.base16().decode(task.getIvHex().get());
            IvParameterSpec iv = new IvParameterSpec(ivData);

            Cipher cipher = Cipher.getInstance(algo.getJavaName());
            cipher.init(mode, key, iv);
            return cipher;
        }
        else {
            Cipher cipher = Cipher.getInstance(algo.getJavaName());
            cipher.init(mode, key);
            return cipher;
        }
    }
}
