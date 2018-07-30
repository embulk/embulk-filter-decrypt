package org.embulk.filter.decrypt;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.io.BaseEncoding;
import org.embulk.config.Config;
import org.embulk.config.ConfigDefault;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.Task;
import org.embulk.config.TaskSource;
import org.embulk.config.YamlTagResolver;
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
import org.embulk.spi.util.RetryExecutor;
import org.slf4j.Logger;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Strings.isNullOrEmpty;
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

    public enum KeyType
    {
        INLINE,
        S3;

        @JsonCreator
        public static KeyType of(String value)
        {
            return KeyType.valueOf(value.toUpperCase());
        }

        @Override
        @JsonValue
        public String toString()
        {
            return super.toString().toLowerCase();
        }
    }

    public interface PluginTask
            extends RetrySupportPluginTask
    {
        @Config("algorithm")
        public Algorithm getAlgorithm();

        @Config("output_encoding")
        @ConfigDefault("\"base64\"")
        public Encoder getOutputEncoding();

        @Config("key_type")
        @ConfigDefault("\"inline\"")
        KeyType getKeyType();

        @Config("key_hex")
        @ConfigDefault("null")
        public Optional<String> getKeyHex();

        public void setKeyHex(Optional<String> key);

        @Config("iv_hex")
        @ConfigDefault("null")
        public Optional<String> getIvHex();

        public void setIvHex(Optional<String> iv);

        @Config("aws_params")
        @ConfigDefault("null")
        public Optional<AWSParams> getAWSParams();

        @Config("column_names")
        public List<String> getColumnNames();
    }

    public interface AWSParams extends Task
    {
        @Config("region")
        public String getRegion();

        @Config("access_key")
        public String getAccessKey();

        @Config("secret_key")
        public String getSecretKey();

        @Config("bucket")
        public String getBucket();

        @Config("full_path")
        public String getFullPath();
    }

    public interface RetrySupportPluginTask extends Task
    {
        @Config("maximum_retries")
        @ConfigDefault("7")
        int getMaximumRetries();

        @Config("initial_retry_interval_millis")
        @ConfigDefault("30000")
        int getInitialRetryIntervalMillis();

        @Config("maximum_retry_interval_millis")
        @ConfigDefault("480000")
        int getMaximumRetryIntervalMillis();
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

    /**
     * Build the common retry executor from some configuration params of plugin task.
     * @param task Plugin task.
     * @return RetryExecutor object
     */
    private static RetryExecutor retryExecutorFrom(RetrySupportPluginTask task)
    {
        return RetryExecutor.retryExecutor()
                .withRetryLimit(task.getMaximumRetries())
                .withInitialRetryWait(task.getInitialRetryIntervalMillis())
                .withMaxRetryWait(task.getMaximumRetryIntervalMillis());
    }

    @VisibleForTesting
    public Map<String, String> retrieveKey(final String bucket, final String path, final AmazonS3 client, RetryExecutor retryExec) throws IOException
    {
        S3Object fullObject = null;
        try {
            fullObject = new DefaultRetryable<S3Object>("Looking up for a single object")
            {
                @Override
                public S3Object call()
                {
                    return client.getObject(new GetObjectRequest(bucket, path));
                }
            }.executeWith(retryExec);
            Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), new YamlTagResolver());
            return (Map<String, String>) yaml.load(fullObject.getObjectContent());
        }
        catch (AmazonServiceException e) {
            // The call was transmitted successfully, but Amazon S3 couldn't process
            // it, so it returned an error response.
            if (e.getErrorType().equals(AmazonServiceException.ErrorType.Client)) {
                // HTTP 40x errors. auth error, bucket doesn't exist, etc. See AWS document for the full list:
                // http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
                if (e.getStatusCode() != 400   // 404 Bad Request is unexpected error
                        || "ExpiredToken".equalsIgnoreCase(e.getErrorCode())) { // if statusCode == 400 && errorCode == ExpiredToken => throws ConfigException
                    throw new ConfigException(e);
                }
            }
            throw e;
        }
        catch (SdkClientException e) {
            // Amazon S3 couldn't be contacted for a response, or the client
            // couldn't parse the response from Amazon S3.
           throw new ConfigException(e);
        }
        finally {
            // To ensure that the network connection doesn't remain open, close any open input streams.
            if (fullObject != null) {
                fullObject.close();
            }
        }
    }

    @VisibleForTesting
    public AmazonS3 newS3Client(final AWSParams awsParams)
    {
        AWSCredentialsProvider awsCredentialsProvider = new AWSCredentialsProvider()
        {
            @Override
            public AWSCredentials getCredentials()
            {
                return new BasicAWSCredentials(awsParams.getAccessKey(), awsParams.getSecretKey());
            }

            @Override
            public void refresh()
            {
            }
        };

        return AmazonS3ClientBuilder.standard()
                .withRegion(awsParams.getRegion())
                .withCredentials(awsCredentialsProvider)
                .build();
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
        switch (task.getKeyType()) {
            case INLINE:
                if (!task.getKeyHex().isPresent()) {
                    throw new ConfigException("Field 'key_hex' is required but not set");
                }
                if (task.getAlgorithm().useIv() && !task.getIvHex().isPresent()) {
                    throw new ConfigException("Algorithm '" + task.getAlgorithm() + "' requires initialization vector. Please generate one and set it to iv_hex option.");
                }
                else if (!task.getAlgorithm().useIv() && task.getIvHex().isPresent()) {
                    log.warn("Algorithm '" + task.getAlgorithm() + "' doesn't use initialization vector. iv_hex is ignore");
                }
                break;
            case S3:
                try {
                    if (!task.getAWSParams().isPresent()) {
                        throw new ConfigException("AWS Params are required for S3 Key type");
                    }
                    AWSParams params = task.getAWSParams().get();
                    RetryExecutor retryExec = retryExecutorFrom(task);
                    AmazonS3 s3Client = newS3Client(params);
                    Map<String, String> keys = retrieveKey(params.getBucket(), params.getFullPath(), s3Client, retryExec);
                    if (keys == null) {
                        throw new ConfigException("Key file is in incorrect format or not enable to be retrieved");
                    }
                    String key = keys.get("key_hex");
                    if (isNullOrEmpty(key)) {
                        throw new ConfigException("Field 'key_hex' is required but not set");
                    }
                    String iv = keys.get("iv_hex");
                    if (task.getAlgorithm().useIv() && isNullOrEmpty(iv)) {
                        throw new ConfigException("Algorithm '" + task.getAlgorithm() + "' requires initialization vector. Please generate one and set it to iv_hex option.");
                    }
                    else if (!task.getAlgorithm().useIv() && !isNullOrEmpty(iv)) {
                        log.warn("Algorithm '" + task.getAlgorithm() + "' doesn't use initialization vector. iv_hex is ignore");
                    }
                    task.setKeyHex(Optional.of(key));
                    task.setIvHex(Optional.of(iv));
                }
                catch (IOException e) {
                    throw new ConfigException(e);
                }
                break;
            default:
                throw new ConfigException(String.format("Key type [%s] is not supported", task.getKeyType().toString()));
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

        byte[] keyData = BaseEncoding.base16().decode(task.getKeyHex().get());
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
