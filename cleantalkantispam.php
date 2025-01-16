<?php

use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;
use Cleantalk\Common\Cleaner\Sanitize;
use Cleantalk\Common\Variables\Server;

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/lib/autoload.php';

class CleantalkAntispam extends Module
{
    private const PLUGIN_VERSION = '1.2.0';

    private $engine;

    public function __construct()
    {
        $this->name = 'cleantalkantispam';
        $this->tab = 'administration';
        $this->version = self::PLUGIN_VERSION;
        $this->engine = 'prestashop-' . $this->version;
        $this->author = 'CleanTalk Developers Team';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = [
            'min' => '1.7.0.0',
            'max' => '8.99.99',
        ];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('CleanTalk AntiSpam Protection');
        $this->description = $this->l('No CAPTCHA, no questions, no animal counting, no puzzles, no math and no spam bots. Universal AntiSpam plugin.');

        $this->confirmUninstall = $this->l('Are you sure you want to uninstall?');
    }

    public function install()
    {
        return parent::install()
            && Configuration::updateValue('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR', 1)
            && $this->registerHook('actionSubmitAccountBefore')
            && $this->registerHook('actionFrontControllerInitAfter')
            && $this->registerHook('actionValidateOrder')
            && $this->registerHook('actionNewsletterRegistrationBefore')
            && $this->registerHook('displayHeader');
    }

    public function uninstall()
    {
        return parent::uninstall()
            && Configuration::deleteByName('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR')
            && Configuration::deleteByName('CLEANTALKANTISPAM_API_KEY');
    }

    public function hookDisplayHeader()
    {
        if (Configuration::get('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR')) {
            return '<script src="https://moderate.cleantalk.org/ct-bot-detector-wrapper.js"></script>';
        }

        return '';
    }

    /**
     * This method handles the module's configuration page
     * @return string The page's HTML content
     */
    public function getContent()
    {
        $output = '';

        // this part is executed only when the form is submitted
        if (Tools::isSubmit('submit' . $this->name)) {
            // retrieve the value set by the user
            $configValue = (string) Tools::getValue('CLEANTALKANTISPAM_API_KEY');
            $enableJs = (int) Tools::getValue('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR');

            // check that the value is valid
            if (empty($configValue) || !Validate::isGenericName($configValue)) {
                // invalid value, show an error
                $output = $this->displayError($this->l('Invalid Configuration value'));
            } else {
                // value is ok, update it and display a confirmation message
                Configuration::updateValue('CLEANTALKANTISPAM_API_KEY', $configValue);
                Configuration::updateValue('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR', $enableJs);
                $output = $this->displayConfirmation($this->l('Settings updated'));
            }
        }

        // display any message, then the form
        return $output . $this->displayForm();
    }

    /**
     * Builds the configuration form
     * @return string HTML code
     */
    public function displayForm()
    {
        // Init Fields form array
        $form = [
            'form' => [
                'legend' => [
                    'title' => $this->l('Settings'),
                ],
                'input' => [
                    [
                        'type' => 'text',
                        'label' => $this->l('API key'),
                        'name' => 'CLEANTALKANTISPAM_API_KEY',
                        'size' => 20,
                        'required' => true,
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->l('Enable CleanTalk JavaScript library'),
                        'name' => 'CLEANTALKANTISPAM_ENABLE_BOTDETECTOR',
                        'required' => false,
                        'is_bool' => true,
                        'values' => [
                            [
                                'id' => 'active_on',
                                'value' => 1,
                                'label' => $this->l('Yes')
                            ],
                            [
                                'id' => 'active_off',
                                'value' => 0,
                                'label' => $this->l('No')
                            ]
                        ]
                    ],
                ],

                'submit' => [
                    'title' => $this->l('Save'),
                    'class' => 'btn btn-default pull-right',
                ],
            ],
        ];

        $helper = new HelperForm();

        // Module, token and currentIndex
        $helper->table = $this->table;
        $helper->name_controller = $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&' . http_build_query(['configure' => $this->name]);
        $helper->submit_action = 'submit' . $this->name;

        // Default language
        $helper->default_form_language = (int) Configuration::get('PS_LANG_DEFAULT');

        // Load current value into the form
        $helper->fields_value['CLEANTALKANTISPAM_API_KEY'] = Tools::getValue('CLEANTALKANTISPAM_API_KEY', Configuration::get('CLEANTALKANTISPAM_API_KEY'));
        $helper->fields_value['CLEANTALKANTISPAM_ENABLE_BOTDETECTOR'] = Tools::getValue('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR', Configuration::get('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR'));

        return $helper->generateForm([$form]);
    }

    public function hookActionSubmitAccountBefore($params)
    {
        $data = Tools::getAllValues();
        $cleantalk_check = $this->checkSpam($data, true);
        if ( $cleantalk_check['allow'] == 0 ) {
            $this->doBlockPage($cleantalk_check['comment']);
        }
        return true;
    }

    public function hookActionFrontControllerInitAfter(&$params)
    {
        // Getting data from the request
        $form_data = Tools::getAllValues();

        // Contact Form integration
        if ( Tools::isSubmit('submitMessage') && isset($params['controller']) && $params['controller'] instanceof \ContactController ) {
            $data['email'] = isset($form_data['from']) ? $form_data['from'] : '';
            $data['message'] = isset($form_data['message']) ? $form_data['message'] : '';
            $data['ct_bot_detector_event_token'] = isset($form_data['ct_bot_detector_event_token']) ? $form_data['ct_bot_detector_event_token'] : '';
            $cleantalk_check = $this->checkSpam($data);
            if ( $cleantalk_check['allow'] == 0 ) {
                $this->doBlockPage($cleantalk_check['comment']);
            }
        }

        // Registration during checkout
        if (isset($form_data['id_gender'], $form_data['firstname'], $form_data['lastname']) &&
            $params['controller'] instanceof \OrderController
        ) {
            $this->hookActionSubmitAccountBefore($params);
        }

        return true;
    }

    public function hookActionValidateOrder($params)
    {
        $order = $params['order'];
        $customer = $params['customer'];

        // There is the NEW order
        if ( is_null($order->getCurrentOrderState()) ) {
            $data['email'] = $customer->email;
            $data['firstname'] = $customer->firstname;
            $data['lastname'] = $customer->lastname;
            $data['message'] = ! is_null($customer->note) ? $customer->note : '';
            $data['post_info']['comment_type'] = 'order';
            $cleantalk_check = $this->checkSpam($data);
            if ( $cleantalk_check['allow'] == 0 ) {
                $history = new OrderHistory();
                $history->id_order = (int) $order->id;
                $history->changeIdOrderState(Configuration::get('PS_OS_CANCELED'), $order);
                $this->doBlockPage($cleantalk_check['comment']);
            }
        }
    }

    public function hookActionNewsletterRegistrationBefore($params)
    {
        $data = [];
        $data['email'] = isset($params['email']) ? $params['email'] : '';
        $data['ct_bot_detector_event_token'] = Tools::getValue('ct_bot_detector_event_token', '');
        $cleantalk_check = $this->checkSpam($data);
        if ($cleantalk_check['allow'] == 0) {
            $params['hookError'] = $cleantalk_check['comment'];
        }
    }

    private function checkSpam($data, $is_check_register = false)
    {
        if ( ! Configuration::get('CLEANTALKANTISPAM_API_KEY') ) {
            return true;
        }

        $ct_request = new CleantalkRequest;

        $ct_request->auth_key        = Configuration::get('CLEANTALKANTISPAM_API_KEY');
        $ct_request->agent           = $this->engine;

        $ct_request->sender_ip       = \Cleantalk\Common\Helper\Helper::ipGet('real', false);
        $ct_request->x_forwarded_for = \Cleantalk\Common\Helper\Helper::ipGet('x_forwarded_for', false);
        $ct_request->x_real_ip       = \Cleantalk\Common\Helper\Helper::ipGet('x_real_ip', false);

        // @ToDo implement SUBMIT TIME
        //$ct_request->submit_time     = $this->submit_time_test();

        $ct_request->sender_email = isset($data['email']) ? $data['email'] : '';
        $ct_request->sender_nickname = isset($data['firstname']) ? $data['firstname'] : '';
        $ct_request->sender_nickname .= isset($data['lastname']) ? ' ' . $data['lastname'] : '';
        $ct_request->message = isset($data['message']) ? $data['message'] : '';
        $ct_request->post_info = isset($data['post_info']) ? $data['post_info'] : '';
        $ct_request->event_token = isset($data['ct_bot_detector_event_token']) ? $data['ct_bot_detector_event_token'] : '';

        $ct                 = new Cleantalk();
        $ct->server_url     = 'https://moderate.cleantalk.org';

        $result = $is_check_register ? $ct->isAllowUser($ct_request) : $ct->isAllowMessage($ct_request);
        $result = json_decode(json_encode($result), true);

        return $result;
    }

    private function doBlockPage($message)
    {
        $ct_die_page = file_get_contents(Cleantalk::getLockPageFile());

        $message_title = '<b style="color: #49C73B;">Clean</b><b style="color: #349ebf;">Talk.</b> Spam protection';
        $back_script = '<script>setTimeout("history.back()", 5000);</script>';
        $back_link = '';
        if ( isset($_SERVER['HTTP_REFERER']) ) {
            $back_link = '<a href="' . Sanitize::cleanUrl(Server::get('HTTP_REFERER')) . '">Back</a>';
        }

        // Translation
        $replaces = array(
            '{MESSAGE_TITLE}' => $message_title,
            '{MESSAGE}'       => $message,
            '{BACK_LINK}'     => $back_link,
            '{BACK_SCRIPT}'   => $back_script
        );

        foreach ( $replaces as $place_holder => $replace ) {
            $ct_die_page = str_replace($place_holder, $replace, $ct_die_page);
        }
        die($ct_die_page);
    }
}
