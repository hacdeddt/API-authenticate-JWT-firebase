#document: https://medium.com/binar-academy/rails-api-jwt-authentication-a04503ea3248
class ApplicationController < ActionController::API
  before_action :authorize_request

  def not_found
    render json: {error: "not_found"}
  end

  def authorize_request
    header = request.headers["token"]
    header = header.split(" ").last if header
    begin
      @decoded = JsonWebToken.decode(header, Settings.alg_jwt)
      @current_user = User.find_by(id: @decoded[:user_id])
    rescue ActiveRecord::RecordNotFound => e
      render json: {errors: e.message}, status: :unauthorized
    rescue JWT::DecodeError => e
      render json: {errors: e.message}, status: :unauthorized
    end
  end
end
