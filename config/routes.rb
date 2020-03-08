Rails.application.routes.draw do
  resources :users
  post "/auth/login", to: "authentication#login"
  get "/auth/logout", to: "authentication#logout"
  get "/*a", to: "application#not_found"
end
