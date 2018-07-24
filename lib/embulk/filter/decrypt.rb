Embulk::JavaPlugin.register_filter(
  "decrypt", "org.embulk.filter.decrypt.DecryptFilterPlugin",
  File.expand_path('../../../../classpath', __FILE__))
