# template.rb

puts "Installing gems"

# ---------------------------------------------------------------------------------------------------------------
# gem setup
# ---------------------------------------------------------------------------------------------------------------
 
gem "mysql"
gem "actionmailer"
gem "authlogic"
rake "gems:install", :sudo => true
 
 
puts "preparing layout"
generate :nifty_layout
 
 
# ---------------------------------------------------------------------------------------------------------------
# database setup
# ---------------------------------------------------------------------------------------------------------------

databasename = ask('What name would you like to use for the database?')
file 'config/database.yml', <<-CODE
  development:
    adapter: mysql
    database: #{databasename}_development
    host: localhost
    username: root
    password:
  
  test:
    adapter: mysql
    database: #{databasename}_test
    host: localhost
    username: root
    password:
CODE
rake("db:create")
 
# ---------------------------------------------------------------------------------------------------------------
# Sessions moved to activerecord
# ---------------------------------------------------------------------------------------------------------------

initializer 'session_store.rb', <<-END
  ActionController::Base.session = { :session_key => '_#{(1..6).map { |x| (65 + rand(26)).chr }.join}_session', :secret => '#{(1..40).map { |x| (65 + rand(26)).chr }.join}' }
  ActionController::Base.session_store = :active_record_store
END
rake('db:sessions:create')
 
 
# ---------------------------------------------------------------------------------------------------------------
# Setup emailer
# ---------------------------------------------------------------------------------------------------------------

generate("mailer Emailer")
initializer 'emailer_config.rb', <<-END
  if ENV["RAILS_ENV"].blank? or ENV["RAILS_ENV"].include?("development") or ENV["RAILS_ENV"].include?("test")
    ActionMailer::Base.delivery_method = :test
    ActionMailer::Base.raise_delivery_errors = false
  else
    ActionMailer::Base.delivery_method = :smtp
    ActionMailer::Base.raise_delivery_errors = true
  end
 
 
  ActionMailer::Base.smtp_settings = {
    :enable_starttls_auto => true,
    :address => "smtp.gmail.com",
    :port => 587,
    :domain => "my domain",
    :authentication => :plain,
    :user_name => "my gmail full username",
    :password => "my password"
  }
END
 
initializer "smtp_tls.rb", <<-CODE
  if RUBY_VERSION=="1.8.6"
    require "openssl"
    require "net/smtp"
 
    Net::SMTP.class_eval do
      private
      def do_start(helodomain, user, secret, authtype)
        raise IOError, 'SMTP session already started' if @started
        check_auth_args user, secret, authtype if user or secret
 
        sock = timeout(@open_timeout) { TCPSocket.open(@address, @port) }
        @socket = Net::InternetMessageIO.new(sock)
        @socket.read_timeout = 60 #@read_timeout
        @socket.debug_output = STDERR #@debug_output
 
        check_response(critical { recv_response() })
        do_helo(helodomain)
 
        raise 'openssl library not installed' unless defined?(OpenSSL)
        starttls
        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.sync_close = true
        ssl.connect
        @socket = Net::InternetMessageIO.new(ssl)
        @socket.read_timeout = 60 #@read_timeout
        @socket.debug_output = STDERR #@debug_output
        do_helo(helodomain)
 
        authenticate user, secret, authtype if user
        @started = true
      ensure
        unless @started
          # authentication failed, cancel connection.
          @socket.close if not @started and @socket and not @socket.closed?
          @socket = nil
        end
      end
 
      def do_helo(helodomain)
        begin
          if @esmtp
            ehlo helodomain
          else
            helo helodomain
          end
        rescue Net::ProtocolError
          if @esmtp
            @esmtp = false
            @error_occured = false
            retry
          end
          raise
        end
      end
 
      def starttls
        getok('STARTTLS')
      end
 
      def quit
        begin
          getok('QUIT')
        rescue EOFError
        end
      end
    end
  end
CODE


file "app/models/emailer.rb", <<-CODE
class Emailer < ActionMailer::Base  
  default_url_options[:host] = "localhost:300"  
  
  def password_reset_instructions(user)  
    subject       "Password Reset Instructions"  
    from          "My Application Support"  
    recipients    user.email
    sent_on       Time.now
    body          :edit_password_reset_url => edit_password_reset_url(user.perishable_token)  
  end  
  
  def added_to_account(user)  
    subject       "You have been added to \#{user.account.name}"
    from          "My Application Support"
    recipients    user.email
    sent_on       Time.now
    body          :account => user.account, :login_url => login_url, :user => user
  end
end
CODE


file "app/views/emailer/password_reset_instructions.erb", <<-CODE
A request to reset your password has been made.  
If you did not make this request, simply ignore this email.  
If you did make this request just click the link below:  

<%=@edit_password_reset_url%>

If the above URL does not work try copying and pasting it into your browser.  
If you continue to have problem please feel free to contact us.
CODE

file "app/views/emailer/added_to_account.erb", <<-CODE
You have been added to the <%=@account.name%> account.

You can login at <%=@login_url%>

email : <%=@user.email%>
password : <%=@user.password%>

If the above URL does not work try copying and pasting it into your browser.  
If you have problem please feel free to contact us.
CODE


# ---------------------------------------------------------------------------------------------------------------
# SetUp webpage controller
# ---------------------------------------------------------------------------------------------------------------

generate :controller, "Webpage index"
route "map.root :controller => :webpage, :action => :index"
file "app/views/webpage/index.html.erb", <<-CODE
  <h1>Welcome to your app</h1>
  <div id="user_nav">
    <% if @current_user %>
      <%= link_to "Edit Account", edit_account_path(@account)%> | 
      <%= link_to "Edit Profile", edit_user_path(@current_user) %> |
      <%= link_to "Logout", logout_path %>
    <% else %>
      <%= link_to "Sign Up", signup_path %> |
      <%= link_to "Login", login_path %>
    <% end %>
  </div>
CODE

# ---------------------------------------------------------------------------------------------------------------
# SetUp Account Model
# ---------------------------------------------------------------------------------------------------------------
generate :nifty_scaffold, "Account name:string new create edit update"
route "map.signup 'signup', :controller => :accounts, :action => :new"
file "app/models/account.rb", <<-CODE
class Account < ActiveRecord::Base
  has_many :users
  accepts_nested_attributes_for :users
  
  def validate    
    if self.users.length == 0
      errors.add(:base, "Must contain atleast one user.")
    end
  end
  
  validates_length_of :name, :within => 3..200, :on => :create, :message => "must be present"
  validates_uniqueness_of :name, :message => "already exists in our database"
  attr_accessible :name, :users_attributes
end
CODE


file "app/controllers/accounts_controller.rb", <<-CODE
class AccountsController < ApplicationController
  def new
    @account = Account.new
  end

  def create
    @account = Account.new(params[:account])
    if @account.save
      flash[:notice] = "Successfully created account."
      redirect_to root_url
    else
      render :action => 'new'
    end
  end

  def edit
    @account = Account.find(params[:id])
  end

  def update
    @account = Account.find(params[:id])
    if @account.update_attributes(params[:account])
      flash[:notice] = "Successfully updated account."
      redirect_to root_url
    else
      render :action => 'edit'
    end
  end
end
CODE

file "app/views/accounts/new.html.erb", <<-CODE
<% title "New Account" %><br/>

<% form_for @account do |f| %>
  <%= f.error_messages %>
	<h3>Account Information</h3>
  <p>
    <%= f.label :name %><br />
    <%= f.text_field :name %>
  </p>

	<hr/>
	<h3>User Information</h3>
	<% @account.users.build if @account.users.empty?%>
	<%f.fields_for :users do |user|%>
		<p>
	    <%= user.label :full_name %><br />
	    <%= user.text_field :full_name, :value => (params[:account][:users_attributes]["0"][:full_name] rescue "") %>
	  </p>
		<p>
	    <%= user.label :email %><br />
	    <%= user.text_field :email, :value => (params[:account][:users_attributes]["0"][:email] rescue "") %>
	  </p>
		<p>
	    <%= user.label :password %><br />
	    <%= user.password_field :password %> <span style="color:#888">(min 4 characters)</span>
	  </p>
		<p>
	    <%= user.label :password_confirmation %><br />
	    <%= user.password_field :password_confirmation %>
	  </p>
	<%end%>

  <p><%= f.submit "Submit" %></p>
<% end %>
CODE

file "app/views/accounts/edit.html.erb", <<-CODE
<% title "Edit Account" %>
<%= render :partial => 'form' %>
<hr/>
<h3>Users</h3>
<ul>
	<% if !@account.users.blank? %>
	  <% for user in @account.users %>
	    <li><%= link_to user.full_name, user_path(user) %></li>
	  <% end %>
	<% else %>
	  <li>No users in this account</li>
	<% end %>
</ul>
<%= link_to "Add another user", new_user_path %>
CODE




# ---------------------------------------------------------------------------------------------------------------
# SetUp User Model
# ---------------------------------------------------------------------------------------------------------------

generate :nifty_scaffold, "User full_name:string email:string password:string password_confirmation:string new create edit update show"
file "app/models/user.rb", <<-CODE
class User < ActiveRecord::Base
  acts_as_authentic
  belongs_to :account
  attr_accessible :email, :full_name, :password, :password_confirmation
  
  validates_length_of :full_name, :within => 3..200, :on => :create, :message => "must be present"
  validates_presence_of :email
  validates_uniqueness_of :email, :message => "is already associated with a user"
  
  before_destroy :confirm_deletable
  def confirm_deletable
    if self.account.users.length==1 and self.account.users.first==self
      raise "Account must have atleast one user" #TODO: can't remove last admin
    end
  end
  
  def deliver_password_reset_instructions!  
    reset_perishable_token!  
    Emailer.deliver_password_reset_instructions(self)  
  end
  
  def deliver_added_to_account!  
    Emailer.deliver_added_to_account(self)  
  end
end
CODE

file "app/controllers/users_controller.rb", <<-CODE
class UsersController < ApplicationController
  before_filter :require_login
  
  def show
    @user = @account.users.find(params[:id])
  end
  
  def new
    @user = @account.users.build
  end
  
  def create
    @user = @account.users.build(params[:user])
    if @user.save
      @user.deliver_added_to_account!
      flash[:notice] = "Successfully created user."
      redirect_to @user
    else
      render :action => 'new'
    end
  end
  
  def edit
    @user = @account.users.find(params[:id])
  end
  
  def update
    @user = @account.users.find(params[:id])
    if @user.update_attributes(params[:user])
      flash[:notice] = "Successfully updated user."
      redirect_to @user
    else
      render :action => 'edit'
    end
  end
  
  def destroy
    @user = @account.users.find(params[:id])
    begin
      @user.destroy
      flash[:notice] = "Successfully destroyed user."
      redirect_to edit_account_path(@account)
    rescue Exception => e
      flash[:error] = e.message
      redirect_to (request.referrer || user_path(@user))
    end
  end
end
CODE

file "app/views/users/new.html.erb", <<-CODE
<% title "New User" %>
<%= render :partial => 'form' %>
<p><%= link_to "View All", edit_account_path(@account) %></p>
CODE

file "app/views/users/edit.html.erb", <<-CODE
<% title "Edit User" %>
<%= render :partial => 'form' %>
<p>
  <%= link_to "Show", @user %> |
  <%= link_to "View All", edit_account_path(@account) %>
</p>
CODE

file "app/views/users/_form.html.erb", <<-CODE
<% form_for @user do |f| %>
  <%= f.error_messages %>
  <p>
    <%= f.label :full_name %><br />
    <%= f.text_field :full_name %>
  </p>
  <p>
    <%= f.label :email %><br />
    <%= f.text_field :email %>
  </p>
  <p>
    <%= f.label :password %><br />
    <%= f.password_field :password %>
  </p>
  <p>
    <%= f.label :password_confirmation %><br />
    <%= f.password_field :password_confirmation %>
  </p>
  <p><%= f.submit "Submit" %></p>
<% end %>
CODE

file "app/views/users/show.html.erb", <<-CODE
<% title "User" %>
<p>
  <strong>Full Name:</strong>
  <%=h @user.full_name %>
</p>
<p>
  <strong>Email:</strong>
  <%=h @user.email %>
</p>
<p>
  <%= link_to "Edit", edit_user_path(@user) %> |
  <%= link_to "Destroy", @user, :confirm => 'Are you sure?', :method => :delete %> |
  <%= link_to "View All", edit_account_path(@account) %>
</p>
CODE


user_migration_name = false
migration_directory = Dir.open("db/migrate")
migration_directory.each{|f|
  user_migration_name = f if f.include?("create_users.rb")
}

file File.join("db", "migrate", user_migration_name), <<-CODE
class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.integer :account_id
      t.string :email
      t.string :full_name
     
      t.string    :crypted_password,    :null => false
      t.string    :password_salt,       :null => false
      t.string    :persistence_token,   :null => false
      t.string    :perishable_token,    :null => false, :default => ""
      t.integer   :login_count,         :null => false, :default => 0
      t.datetime  :last_login_at 
      
      t.timestamps
    end
    add_index :users, :account_id
    add_index :users, :email
    add_index :users, :perishable_token 
  end
  
  def self.down
    remove_index :users, :perishable_token 
    remove_index :users, :email
    remove_index :users, :account_id
    drop_table :users
  end
end
CODE

# ---------------------------------------------------------------------------------------------------------------
# SetUp sessions
# ---------------------------------------------------------------------------------------------------------------
generate :session, "user_session"
generate :nifty_scaffold, "user_sessions", "--skip-model", "username:string password:string new destroy"
route "map.login 'login', :controller => :user_sessions, :action => :new"
route "map.logout 'logout', :controller => :user_sessions, :action => :destroy"

file "app/controllers/user_sessions_controller.rb", <<-CODE
class UserSessionsController < ApplicationController
  def new
    @user_session = UserSession.new
  end
  
  def create
    @user_session = UserSession.new(params[:user_session])
    if @user_session.save
      flash[:notice] = "Successfully logged in."
      redirect_to root_url
    else
      render :action => 'new'
    end
  end

  def destroy
    @user_session = UserSession.find
    @user_session.destroy
    flash[:notice] = "Successfully logged out."
    redirect_to root_url
  end
  
  def forgot_my_password
    if request.post?
    end
  end
end
CODE

file "app/views/user_sessions/new.html.erb", <<-CODE
<% title "Login" %>

<% form_for @user_session do |f| %>
  <%= f.error_messages %>
  <p>
    <%= f.label :email %><br />
    <%= f.text_field :email %>
  </p>
  <p>
    <%= f.label :password %><br />
    <%= f.password_field :password %>
  </p>
  <p><%= f.submit "Submit" %></p>
  <%=link_to "Forgot your password?", new_password_reset_path %>
<% end %>
CODE

# ---------------------------------------------------------------------------------------------------------------
# password reset code
# ---------------------------------------------------------------------------------------------------------------

generate :controller, "password_resets"
route "map.resources :password_resets"

file "app/controllers/password_resets_controller.rb", <<-CODE
#This code was found on the BinaryLogic blog http://www.binarylogic.com/2008/11/16/tutorial-reset-passwords-with-authlogic/

class PasswordResetsController < ApplicationController  
  before_filter :require_no_user  
  before_filter :load_user_using_perishable_token, :only => [:edit, :update] 
  
  def new  
    render  
  end  
  
  def create  
    @user = User.find_by_email(params[:email])  
    if @user  
      @user.deliver_password_reset_instructions!  
      flash[:notice] = "Instructions to reset your password have been emailed to you. " +  
      "Please check your email."  
      redirect_to root_url  
    else  
      flash[:error] = "No user was found with that email address"  
      render :action => :new  
    end  
  end  
  
  def edit  
    render  
  end  

  def update  
    @user.password = params[:user][:password]  
    @user.password_confirmation = params[:user][:password_confirmation]  
    if @user.save  
      flash[:notice] = "Password successfully updated"  
      redirect_to account_url  
    else  
      render :action => :edit  
    end  
  end
  
  private  
  
  def load_user_using_perishable_token  
    @user = User.find_using_perishable_token(params[:id])  
    unless @user  
      flash[:notice] = "We're sorry, but we could not locate your account. " +  
      "If you are having issues try copying and pasting the URL " +  
      "from your email into your browser or restarting the " +  
      "reset password process."  
      redirect_to root_url  
    end
  end
  
end
CODE


file "app/views/password_resets/new.html.erb", <<-CODE
<h1>Forgot Password</h1>
 
Fill out the form below and instructions to reset your password will be emailed to you:<br />
<br />
 
<% form_tag password_resets_path do %>
  <label>Email:</label><br />
  <%= text_field_tag "email" %><br />
  <br />
  <%= submit_tag "Reset my password" %>
<% end %>
CODE

file "app/views/password_resets/edit.html.erb", <<-CODE
<h1>Change My Password</h1>
 
<% form_for @user, :url => password_reset_path, :method => :put do |f| %>
  <%= f.error_messages %>
  <%= f.label :password %><br />
  <%= f.password_field :password %><br />
  <br />
  <%= f.label :password_confirmation %><br />
  <%= f.password_field :password_confirmation %><br />
  <br />
  <%= f.submit "Update my password and log me in" %>
<% end %>
CODE

# ---------------------------------------------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------------------------------------------

file "app/controllers/application_controller.rb", <<-CODE
class ApplicationController < ActionController::Base
  helper :all
  protect_from_forgery 

  filter_parameter_logging :password, :password_confirmation

  before_filter :check_and_set_athentication
  def check_and_set_athentication
    if current_user
      @current_user = current_user
      @account = @current_user.account
    end
  end

  def require_login
    unless @current_user
      flash[:notice] = "you must be logged in to access this area"
      redirect_to login_path
    end
  end
  
  def require_no_user
    if @current_user
      flash[:notice] = "You can't be logged in to access this area."
      redirect_to login_path
    end
  end

  private

  def current_user_session
    return @current_user_session if defined?(@current_user_session)
    @current_user_session = UserSession.find
  end

  def current_user
    return @my_current_user if defined?(@my_current_user)
    @my_current_user = current_user_session && current_user_session.record
  end
end

CODE
 
run "rm public/index.html"
 
 

 
 
 
# ---------------------------------------------------------------------------------------------------------------
# perform basic git setup
# ---------------------------------------------------------------------------------------------------------------
puts "Setting up Git"
 
git :init
run "echo 'TODO add readme content' > README"
run "touch tmp/.gitignore log/.gitignore vendor/.gitignore"
 
file ".gitignore", <<-END
log/*.log
tmp/**/*
config/database.yml
db/*.sql
END
 
git :add => "."
git :commit => "-a -m 'Initial commit'"


puts "!!!!!!!!!SUCCESS!!!!!!!!!!!!\n\t(Don't forget to migrate.)"