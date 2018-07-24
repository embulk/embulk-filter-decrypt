The reviewers make sure that the PR these checklist these boxes are checked.
Please see more details: https://treasure-data.atlassian.net/wiki/display/EN/Review+source+codes+and+documents+of+Embulk+plugins
 
#### Communication Channels and Connections
 
* [ ] Does opt secure communication standard? Such as HTTPS, SSH, SFTP, SMTP STARTTLS. If not, check with Treasure Data CISO.
* [ ] Does communicate only through appropriately encrypted channels, such as HTTPS with publicly-certified SSL. No self-certified.
* [ ] Does communicate customer data only through authenticated channels.
 
#### Communication Targets
 
* [ ] Does NOT connect to unexpected external sites, which are not set in the configuration files by the customer.
* [ ] Does NOT connect to Treasure Data's internal endpoints, such as: “v3/job/:id/set_started” callback endpoint.
 
#### (Persistent) Side Channels
 
* [ ] Does NOT store any protected data (Customer Data) in any file, including temporary files.
* [ ] Does NOT dump any protected data (Customer Data) in log messages.
* [ ] Does NOT throw any protected data (Customer Data) in exception messages.
 
#### Runtime Environments
 
* [ ] Does NOT execute any shell command?
* [ ] Does NOT read any files on the running instance? Such as: "/etc/passwords". It’s ok to read temporary files that the plugin wrote.
* [ ] Does use to create temporary files by spi.TempFileSpace utility to avoid the conflict of the file names.
* [ ] Does NOT get environment variables or JVM system properties at runtime? Such as AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in environment variables
 
#### Data in Repository
 
* [ ] Does NOT contain any API key (even if revoked) in the source code repository.
* [ ] Does NOT contain any password (even if revoked) in the source code repository.
* [ ] Does NOT contain any Personally Identifiable Information (PII) in the source code repository. If needed for test data, make them easy to understand they are example data. (e.g. using example.com)
* [ ] Does NOT contain any Customer Data in the source code repository.
 
#### Resources
 
* [ ] Does close all network connections and pooled connections during Embulk transactions after "committing" or "rolling-back".
* [ ] Does deallocate memory objects (especially cache in static variables) during Embulk transactions.
* [ ] Does remove (temporary) files during Embulk transactions.
* [ ] Does terminate all sub-threads and sub-processes during Embulk transactions.
 
#### Dependency Libraries
 
* [ ] Does NOT refer Maven repositories through non-secure HTTP?
* List all depending libraries.
* [ ] Does ensure all the libraries do not have security incidents reported.
* [ ] Does reconfirm all other security checks with the library usage, such as "Does communicate only through appropriately encrypted channels"