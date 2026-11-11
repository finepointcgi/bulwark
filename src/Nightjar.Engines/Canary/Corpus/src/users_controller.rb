# Canary: params interpolated into a SQL fragment.
class UsersController
  def show
    User.where("name = '#{params[:name]}'")
  end
end
