source 'https://rubygems.org'

gemspec

gem 'jwt', '~> 2'
gem 'rake', '~> 13'

group :development do
  gem 'dotenv', '~> 2'
  gem 'pry', '~> 0'
  gem 'rubocop', '~> 1', require: false
  gem 'shotgun', '~> 0', '>= 0.9.2'
  gem 'sinatra', '~> 3'
  gem 'thin', '~> 1'
  gem 'omniauth-oauth2', git: 'https://github.com/ViktorArkaliuk/omniauth-oauth2', branch: 'master', require: false
end

group :test do
  gem 'guard-rspec', '~> 4', require: false
  gem 'listen', '~> 3'
  gem 'rack-test', '~> 2', '>= 2.0.2'
  gem 'rspec', '~> 3'
  gem 'simplecov-cobertura', '~> 2'
  gem 'webmock', '~> 3'
  gem 'multi_json', '~> 1'
end
