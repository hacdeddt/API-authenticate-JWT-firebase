class AuthenticationController < ApplicationController
  skip_before_action :authorize_request, only: :login

  # POST /auth/login
  def login
    token = request.headers["idToken"]
    verify = FirebaseAuth::Auth.verify_id_token(token)
    return render json: {error: "Token is Invalid"}, status: unauthorized if verify.nil?
    email = verify.first.email rescue nil
    name = verify.first.name rescue nil
    uuid = verify.first.user_id rescue nil
    @user = User.find_by(email: email)
    create_user(email, name, uuid) if @user.nil?
    time = Time.now + 24.hours.to_i
    token = JsonWebToken.encode(user_id: @user.id)
    render json: {token: token, exp: time.strftime("%m-%d-%Y %H:%M"),
                  name: @user.name}, status: :ok
  end

  def logout
    exp = Time.now.yesterday
    token = JsonWebToken.encode({user_id: @current_user.id}, exp)
    render json: {token: token, exp: Time.now.yesterday.strftime("%m-%d-%Y %H:%M"),
                  name: @current_user.name}, status: :ok
  end

  private

  def create_user(email, name, uuid)
    @user = User.new(id: uuid, email: email, name: name)
    return render json: {errors: @user.errors} unless @user.save
  end

  # def login_params
  #   params.permit(:email, :password)
  # end
end
