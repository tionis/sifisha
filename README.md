# SiFiSha - Simple File Share

Simple File Share is a solution I built for myself to share files and directories from me (the admin) to many users.  
The core of SiFiSha is simple: The proxy (this application) connects to a storage backend via sftp and exposes the filesystem beneath it. It also applies some authentication logic based on `auth` config files in directories.

## Auth (Authorization and Authentication)

On file access the SiFiSha walks up the hierararchy until it find an auth config and applies it to the user.  
Auth configs (AC) can inherit from AC's above it in the hierarchy.  
Two main auth types are planned so far:

### Basic Auth

This is a htpasswd style basic auth that the users need to provide via basic auth. The sysadmin can also use paths in this config to share user-password pairs between different ACs.

### oAuth (github)

This is a github oauth strategy that can restrict users based on name and org and team membership.

### Future of auth system

For the initial implementation auth is implemented in yaml files, but in the future I want to support some config, general scripting or logic language to drive the authorization logic to make the server implementation more generic and powerful.
