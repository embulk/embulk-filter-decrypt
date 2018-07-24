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
import org.embulk.spi.Column;
import org.embulk.spi.ColumnVisitor;
import org.embulk.spi.DataException;
import org.embulk.spi.Exec;
import org.embulk.spi.FilterPlugin;
import org.embulk.spi.Page;
import org.embulk.spi.PageBuilder;
import org.embulk.spi.PageOutput;
import org.embulk.spi.PageReader;
import org.embulk.spi.Schema;
import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
            EnumSet<Algorithm> algos = EnumSet.allOf(Algorithm.class);
            for (Algorithm algo : algos) {
                for (String n : algo.displayNames) {
                    if (n.equals(name)) {
                        return algo;
                    }
                }
            }
            throw new ConfigException(format("Unsupported algorithm '%s'. Supported algorithms are %s",
                    name,
                    join(algos, ", ")));
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

        public byte[] decode(String s)
        {
            return encoding.decode(s);
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
    public PageOutput open(TaskSource taskSource, final Schema inputSchema,
           final Schema outputSchema, final PageOutput output)
    {
        final PluginTask task = taskSource.loadTask(PluginTask.class);

        final Cipher cipher;
        try {
            cipher = getCipher(Cipher.DECRYPT_MODE, task);
        }
        catch (Exception e) {
            throw new DataException(e);
        }

        final int[] targetColumns = new int[task.getColumnNames().size()];
        int i = 0;
        for (String name : task.getColumnNames()) {
            targetColumns[i++] = inputSchema.lookupColumn(name).getIndex();
        }

        return new PageOutput() {
            private final PageReader pageReader = new PageReader(inputSchema);
            private final PageBuilder pageBuilder = new PageBuilder(Exec.getBufferAllocator(), outputSchema, output);
            private final Encoder encoder = task.getOutputEncoding();

            @Override
            public void finish()
            {
                pageBuilder.finish();
            }

            @Override
            public void close()
            {
                pageBuilder.close();
            }

            private boolean isTargetColumn(Column c)
            {
                for (int i = 0; i < targetColumns.length; i++) {
                    if (c.getIndex() == targetColumns[i]) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public void add(Page page)
            {
                pageReader.setPage(page);

                while (pageReader.nextRecord()) {
                    inputSchema.visitColumns(new ColumnVisitor() {
                        @Override
                        public void booleanColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setBoolean(column, pageReader.getBoolean(column));
                            }
                        }

                        @Override
                        public void longColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setLong(column, pageReader.getLong(column));
                            }
                        }

                        @Override
                        public void doubleColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setDouble(column, pageReader.getDouble(column));
                            }
                        }

                        @Override
                        public void stringColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else if (isTargetColumn(column)) {
                                String orig = pageReader.getString(column);
                                byte[] decoded = encoder.decode(orig);
                                byte[] decrypted;

                                try {
                                    decrypted = cipher.doFinal(decoded);
                                }
                                catch (BadPaddingException ex) {
                                    // this must not happen because PKCS5Padding is always enabled
                                    throw new DataException(ex);
                                }
                                catch (IllegalBlockSizeException ex) {
                                    // this must not happen because always doFinal is called
                                    throw new DataException(ex);
                                }
                                pageBuilder.setString(column, new String(decrypted));
                            }
                            else {
                                pageBuilder.setString(column, pageReader.getString(column));
                            }
                        }

                        @Override
                        public void timestampColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setTimestamp(column, pageReader.getTimestamp(column));
                            }
                        }

                        @Override
                        public void jsonColumn(Column column)
                        {
                            if (pageReader.isNull(column)) {
                                pageBuilder.setNull(column);
                            }
                            else {
                                pageBuilder.setJson(column, pageReader.getJson(column));
                            }
                        }
                    });
                    pageBuilder.addRecord();
                }
            }
        };
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
