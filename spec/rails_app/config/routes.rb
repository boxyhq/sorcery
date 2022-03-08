AppRoot::Application.routes.draw do
  root to: 'application#index'

  controller :sorcery do
    get :test_login
    get :test_logout
    get :some_action
    post :test_return_to
    get :test_auto_login
    post :test_login_with_remember_in_login
    get :test_login_from_cookie
    get :test_login_from
    get :test_logout_with_remember
    get :test_logout_with_forget_me
    get :test_logout_with_force_forget_me
    get :test_invalidate_active_session
    get :test_should_be_logged_in
    get :test_create_from_provider
    get :test_add_second_provider
    get :test_return_to_with_external
    get :test_login_from
    get :test_login_from_twitter
    get :test_login_from_facebook
    get :test_login_from_github
    get :test_login_from_paypal
    get :test_login_from_wechat
    get :test_login_from_microsoft
    get :test_login_from_google
    get :test_login_from_liveid
    get :test_login_from_vk
    get :test_login_from_jira
    get :test_login_from_salesforce
    get :test_login_from_slack
    get :test_login_from_instagram
    get :test_login_from_auth0
    get :test_login_from_line
    get :test_login_from_discord
    get :test_login_from_battlenet
    get :test_login_from_boxyhqsaml
    get :login_at_test
    get :login_at_test_twitter
    get :login_at_test_facebook
    get :login_at_test_github
    get :login_at_test_paypal
    get :login_at_test_wechat
    get :login_at_test_microsoft
    get :login_at_test_google
    get :login_at_test_liveid
    get :login_at_test_vk
    get :login_at_test_jira
    get :login_at_test_salesforce
    get :login_at_test_slack
    get :login_at_test_instagram
    get :login_at_test_auth0
    get :login_at_test_line
    get :login_at_test_discord
    get :login_at_test_battlenet
    get :login_at_test_boxyhqsaml
    get :test_return_to_with_external
    get :test_return_to_with_external_twitter
    get :test_return_to_with_external_facebook
    get :test_return_to_with_external_github
    get :test_return_to_with_external_paypal
    get :test_return_to_with_external_wechat
    get :test_return_to_with_external_microsoft
    get :test_return_to_with_external_google
    get :test_return_to_with_external_liveid
    get :test_return_to_with_external_vk
    get :test_return_to_with_external_jira
    get :test_return_to_with_external_salesforce
    get :test_return_to_with_external_slack
    get :test_return_to_with_external_instagram
    get :test_return_to_with_external_auth0
    get :test_return_to_with_external_line
    get :test_return_to_with_external_discord
    get :test_return_to_with_external_battlenet
    get :test_return_to_with_external_boxyhqsaml
    get :test_http_basic_auth
    get :some_action_making_a_non_persisted_change_to_the_user
    post :test_login_with_remember
    get :test_create_from_provider_with_block
    get :login_at_test_with_state
  end
end
