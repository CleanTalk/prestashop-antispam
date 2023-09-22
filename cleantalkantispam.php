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

    private string $engine;

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
            && $this->registerHook('actionSubmitAccountBefore')
            && $this->registerHook('actionFrontControllerInitAfter');
    }

    public function uninstall()
    {
        return parent::uninstall()
            && Configuration::deleteByName('CLEANTALKANTISPAM_API_KEY');
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

            // check that the value is valid
            if (empty($configValue) || !Validate::isGenericName($configValue)) {
                // invalid value, show an error
                $output = $this->displayError($this->l('Invalid Configuration value'));
            } else {
                // value is ok, update it and display a confirmation message
                Configuration::updateValue('CLEANTALKANTISPAM_API_KEY', $configValue);
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

        return $helper->generateForm([$form]);
    }

    public function hookActionSubmitAccountBefore($params)
    {
        $data = Tools::getAllValues();
        return $this->checkSpam($data, true);
    }

    public function hookActionFrontControllerInitAfter(&$params)
    {
        // Contact Form integration
        if ( Tools::isSubmit('submitMessage') && isset($params['controller']) && $params['controller'] instanceof \ContactController ) {
            $form_data = Tools::getAllValues();
            $data['email'] = isset($form_data['from']) ? $form_data['from'] : '';
            $data['message'] = isset($form_data['message']) ? $form_data['message'] : '';
            return $this->checkSpam($data);
        }
        return true;
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

        // @ToDo implement JS checking
        //$ct_request->js_on           = $this->get_ct_checkjs($_COOKIE);

        // @ToDo implement SUBMIT TIME
        //$ct_request->submit_time     = $this->submit_time_test();

        $ct_request->sender_email = isset($data['email']) ? $data['email'] : '';
        $ct_request->sender_nickname = isset($data['firstname']) ? $data['firstname'] : '';
        $ct_request->sender_nickname .= isset($data['lastname']) ? ' ' . $data['lastname'] : '';
        $ct_request->message = isset($data['message']) ? ' ' . $data['message'] : '';

        $ct                 = new Cleantalk();
        $ct->server_url     = 'https://moderate.cleantalk.org';

        $result = $is_check_register ? $ct->isAllowUser($ct_request) : $ct->isAllowMessage($ct_request);
        $result = json_decode(json_encode($result), true);

        if ($result['allow'] == 0) {
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
                '{MESSAGE}'       => $result['comment'],
                '{BACK_LINK}'     => $back_link,
                '{BACK_SCRIPT}'   => $back_script
            );

            foreach ( $replaces as $place_holder => $replace ) {
                $ct_die_page = str_replace($place_holder, $replace, $ct_die_page);
            }
            die($ct_die_page);
        }
        return true;
    }
}
