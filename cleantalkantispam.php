<?php

use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;
use Cleantalk\Common\Cleaner\Sanitize;
use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Variables\Server;

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/lib/autoload.php';

class CleantalkAntispam extends Module
{
    private const PLUGIN_VERSION = '2.1.1';

    /**
     * Payment modules that create the order on the shop, without leaving the site.
     * Off-site modules (Amazon Pay, Redsys and similar) are checked earlier.
     */
    private const ONSITE_PAYMENT_MODULES = [
        'ps_checkpayment',
        'ps_wirepayment',
        'ps_cashondelivery',
    ];

    private $engine;

    /**
     * Flag to prevent several request per a runtime
     * @var bool
     */
    private $registrationAlreadyProcessed = false;

    /**
     * Order spam decision already made during this request.
     * @var bool
     */
    private $orderSpamChecked = false;

    /**
     * Guard so the cancelled order we create does not re-enter the spam check.
     * @var bool
     */
    private $creatingBlockedOrder = false;

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
            'max' => '9.0.3',
        ];
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('CleanTalk AntiSpam Protection');
        $this->description = $this->l('No CAPTCHA, no questions, no animal counting, no puzzles, no math and no spam bots. Universal AntiSpam plugin.');

        $this->confirmUninstall = $this->l('Are you sure you want to uninstall?');

        if ($this->id && !Configuration::get('CLEANTALKANTISPAM_ORDER_HOOKS_V2')) {
            $hooksReady = $this->registerHook('actionDispatcherBefore')
                && $this->registerHook('actionObjectOrderAddBefore')
                && $this->unregisterHook('actionValidateOrder');
            if ($hooksReady) {
                Configuration::updateValue('CLEANTALKANTISPAM_ORDER_HOOKS_V2', 1);
                Db::getInstance()->update('module', [
                    'version' => pSQL(self::PLUGIN_VERSION),
                ], 'id_module = ' . (int) $this->id);
            }
        }

        // Check if the registration form is submitted
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST'
            && isset($_POST['submitCreate']) && $_POST['submitCreate'] === '1'
            && isset($_POST['email']) && $_POST['email'] !== ''
        ) {
            $this->checkRegistrationSpam();
        }
    }

    public function install()
    {
        return parent::install()
            && Configuration::updateValue('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR', 1)
            && $this->registerHook('actionSubmitAccountBefore')
            && $this->registerHook('actionBeforeSubmitAccount')
            && $this->registerHook('actionFrontControllerInitAfter')
            && $this->registerHook('actionDispatcherBefore')
            && $this->registerHook('actionObjectOrderAddBefore')
            && $this->registerHook('actionNewsletterRegistrationBefore')
            && Configuration::updateValue('CLEANTALKANTISPAM_ORDER_HOOKS_V2', 1)
            && $this->registerHook('displayHeader');
    }

    public function uninstall()
    {
        return parent::uninstall()
            && Configuration::deleteByName('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR')
            && Configuration::deleteByName('CLEANTALKANTISPAM_API_KEY')
            && Configuration::deleteByName('CLEANTALKANTISPAM_ORDER_HOOKS_V2');
    }

    public function hookDisplayHeader()
    {
        if (Configuration::get('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR')) {
            return '<script src="https://fd.cleantalk.org/ct-bot-detector-wrapper.js" async="async"></script>';
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
        return $this->checkRegistrationSpam();
    }

    /**
     * PrestaShop AuthController calls this hook (actionBeforeSubmitAccount)
     * for registration form submissions (submitAccount / submitGuestAccount).
     */
    public function hookActionBeforeSubmitAccount($params)
    {
        return $this->checkRegistrationSpam();
    }

    public function hookActionFrontControllerInitAfter(&$params)
    {
        // Getting data from the request
        $form_data = Tools::getAllValues();

        // Form Builder Pro (gformbuilderpro) integration
        if (isset($form_data['idform']) && isset($form_data['gSubmitForm']) && $form_data['gSubmitForm'] == '1') {
            $data = $this->extractFormBuilderData($form_data);
            $data['ct_bot_detector_event_token'] = Tools::getValue('ct_bot_detector_event_token', '');
            $data['post_info']['comment_type'] = 'contact_form_gformbuilderpro';
            $cleantalk_check = $this->checkSpam($data);
            if ($cleantalk_check['allow'] == 0) {
                if (!empty($form_data['usingajax']) && $form_data['usingajax'] == '1') {
                    $this->doBlockFormBuilderAjax($cleantalk_check['comment']);
                } else {
                    $this->doBlockPage($cleantalk_check['comment']);
                }
            }
        }

        // Contact Form integration
        if ( Tools::isSubmit('submitMessage') && isset($params['controller']) && $params['controller'] instanceof \ContactController ) {
            $data['email'] = isset($form_data['from']) ? $form_data['from'] : '';
            $data['message'] = isset($form_data['message']) ? $form_data['message'] : '';
            $data['ct_bot_detector_event_token'] = Tools::getValue('ct_bot_detector_event_token', '');
            $data['post_info']['comment_type'] = 'contact_form_prestashop_contact';
            $cleantalk_check = $this->checkSpam($data);
            if ( $cleantalk_check['allow'] == 0 ) {
                $this->doBlockPage($cleantalk_check['comment']);
            }
        }

        // Creative Elements contact form integration (AJAX)
        if ( Tools::isSubmit('submitMessage') && isset($params['controller']) && $this->isCreativeElementsAjaxController($params['controller']) ) {
            $data = [];
            $data['email'] = isset($form_data['from']) ? $form_data['from'] : '';
            $data['message'] = isset($form_data['message']) ? $form_data['message'] : '';
            $data['ct_bot_detector_event_token'] = Tools::getValue('ct_bot_detector_event_token', '');
            $data['post_info']['comment_type'] = 'contact_form_creative_elements';
            $cleantalk_check = $this->checkSpam($data);
            if ( $cleantalk_check['allow'] == 0 ) {
                $this->doBlockAjax($cleantalk_check['comment']);
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

    /**
     * Check if the controller is Creative Elements AJAX controller.
     *
     * @param mixed $controller
     * @return bool
     */
    private function isCreativeElementsAjaxController($controller)
    {
        if ( ! is_object($controller) ) {
            return false;
        }

        $controller_class = get_class($controller);

        return stripos($controller_class, 'creativeelements') !== false
            && stripos($controller_class, 'ajax') !== false;
    }

    /**
     * Block AJAX request with JSON error response.
     * Format compatible with Creative Elements contact form.
     *
     * @param string $message
     * @return void
     */
    private function doBlockAjax($message)
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0');
        die(json_encode([
            'success' => '',
            'errors' => [$message],
        ]));
    }

    /**
     * Block Form Builder Pro AJAX request with JSON error response.
     * Format compatible with gformbuilderpro module.
     *
     * @param string $message
     * @return void
     */
    private function doBlockFormBuilderAjax($message)
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0');

        $error_html = '<div id="thankyou-page">' .
                      '<div class="alert alert-danger">' .
                      '<button type="button" class="close" data-dismiss="alert">&times;</button>' .
                      htmlspecialchars($message, ENT_QUOTES, 'UTF-8') .
                      '</div>' .
                      '</div>';

        die(json_encode([
            'errors' => '1',
            'thankyou' => $error_html,
            'autoredirect' => false,
            'timedelay' => 0,
            'redirect_link' => '',
        ]));
    }

    /**
     * Off-site payments (Amazon Pay, Redsys): the customer is about to leave the shop.
     * The hook runs before the controller, before the database write and before the redirect.
     */
    public function hookActionDispatcherBefore($params)
    {
        if ($this->creatingBlockedOrder || $this->orderSpamChecked || !$this->isOffsitePaymentRequest($params)) {
            return;
        }
        // A signed return or a server notification is not a new checkout. The order is checked on insert.
        if ($this->isPaymentGatewayCallback() || $this->hasPaymentGatewayPayload()) {
            return;
        }

        $this->loadCheckoutContext();
        $customer = $this->getCheckoutCustomer();
        $cart = $this->getCheckoutCart();
        if (!$customer || !$cart || !$this->isCartReadyForOrder($cart) || $cart->OrderExists()) {
            return;
        }

        $decision = $this->evaluateOrderSpam($customer);
        $this->orderSpamChecked = true;
        if ($decision === null) {
            return;
        }

        $this->blockOrder($customer, $cart, $decision['comment'], (string) Tools::getValue('module'));
    }

    /**
     * On-site checkout: last point before the order row is inserted.
     * Also covers payment callbacks that create the order after the customer has already left the shop.
     */
    public function hookActionObjectOrderAddBefore($params)
    {
        if ($this->creatingBlockedOrder || $this->orderSpamChecked) {
            return;
        }
        if (empty($params['object']) || !($params['object'] instanceof Order)) {
            return;
        }

        $order = $params['object'];
        if (!$this->shouldCheckOrderCreation($order)) {
            return;
        }

        $customer = new Customer((int) $order->id_customer);
        if (!Validate::isLoadedObject($customer)) {
            return;
        }

        $decision = $this->evaluateOrderSpam($customer);
        $this->orderSpamChecked = true;
        if ($decision === null) {
            return;
        }

        $cart = new Cart((int) $order->id_cart);
        $this->blockOrder(
            $customer,
            $cart,
            $decision['comment'],
            (string) $order->module,
            (string) $order->payment
        );
    }

    /**
     * @param array $params
     * @return bool
     */
    private function isOffsitePaymentRequest($params)
    {
        if (!is_array($params) || !isset($params['controller_type'])) {
            return false;
        }
        if ((int) $params['controller_type'] !== Dispatcher::FC_MODULE || Tools::getValue('fc') !== 'module') {
            return false;
        }

        $moduleName = (string) Tools::getValue('module');
        if ($moduleName === '' || in_array($moduleName, self::ONSITE_PAYMENT_MODULES, true)) {
            return false;
        }

        return $this->isActivePaymentModule($moduleName);
    }

    /**
     * @param string $moduleName
     * @return bool
     */
    private function isActivePaymentModule($moduleName)
    {
        foreach (Module::getPaymentModules() as $module) {
            if (isset($module['name']) && $module['name'] === $moduleName) {
                return true;
            }
        }

        return false;
    }

    /**
     * Signed payment result (Redsys, Amazon Pay, PayPal and similar).
     * Present on both the server notification and the customer's browser return.
     *
     * @return bool
     */
    private function hasPaymentGatewayPayload()
    {
        $gatewayKeys = [
            'Ds_Signature',
            'Ds_MerchantParameters',
            'amazonCheckoutSessionId',
            'amazon_Login_accessToken',
            'txn_id',
            'payment_status',
        ];
        foreach ($gatewayKeys as $key) {
            if (Tools::getValue($key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Server-to-server payment notifications must not receive the HTML block page.
     * A browser that still has the customer session and asks for HTML is not a callback.
     *
     * @return bool
     */
    private function isPaymentGatewayCallback()
    {
        if ($this->isCustomerBrowserRequest()) {
            return false;
        }
        if ($this->hasPaymentGatewayPayload()) {
            return true;
        }

        $context = Context::getContext();
        $hasCustomer = isset($context->cookie->id_customer) && (int) $context->cookie->id_customer > 0;
        $method = isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : '';

        return $method === 'POST' && !$hasCustomer;
    }

    /**
     * @return bool
     */
    private function isCustomerBrowserRequest()
    {
        $context = Context::getContext();
        $hasCustomer = isset($context->cookie->id_customer) && (int) $context->cookie->id_customer > 0;
        $accept = isset($_SERVER['HTTP_ACCEPT']) ? (string) $_SERVER['HTTP_ACCEPT'] : '';

        return $hasCustomer && strpos($accept, 'text/html') !== false;
    }

    /**
     * Back office, webservice and CLI create orders outside checkout.
     *
     * @return bool
     */
    private function isNonCheckoutContext()
    {
        if (PHP_SAPI === 'cli' || defined('_PS_ADMIN_DIR_')) {
            return true;
        }

        $context = Context::getContext();
        if (isset($context->employee) && Validate::isLoadedObject($context->employee)) {
            return true;
        }
        if (isset($context->controller) && $context->controller instanceof AdminController) {
            return true;
        }

        $script = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';

        return $script !== '' && strpos($script, '/webservice/') !== false;
    }

    /**
     * Check the insert only when a payment module is placing the order, or a gateway is notifying the shop.
     *
     * @param Order $order
     * @return bool
     */
    private function shouldCheckOrderCreation(Order $order)
    {
        if ($this->isNonCheckoutContext()) {
            return false;
        }

        $moduleName = (string) $order->module;
        if ($moduleName !== '' && $this->isInstalledPaymentModule($moduleName)) {
            return true;
        }

        return $this->isPaymentGatewayCallback() || $this->hasPaymentGatewayPayload();
    }

    /**
     * @param string $moduleName
     * @return bool
     */
    private function isInstalledPaymentModule($moduleName)
    {
        if ($moduleName === '' || !Validate::isModuleName($moduleName)) {
            return false;
        }

        $module = Module::getInstanceByName($moduleName);

        return $module instanceof PaymentModule && $module->active;
    }

    private function loadCheckoutContext()
    {
        $context = Context::getContext();
        if (!isset($context->cookie)) {
            return;
        }

        $idCart = (int) $context->cookie->id_cart;
        $idCustomer = (int) $context->cookie->id_customer;
        if ($idCart && (!isset($context->cart) || !(int) $context->cart->id)) {
            $context->cart = new Cart($idCart);
        }
        if ($idCustomer && (!isset($context->customer) || !(int) $context->customer->id)) {
            $context->customer = new Customer($idCustomer);
        }
    }

    /**
     * @return Customer|null
     */
    private function getCheckoutCustomer()
    {
        $context = Context::getContext();
        if (isset($context->customer) && Validate::isLoadedObject($context->customer)) {
            return $context->customer;
        }
        if (!isset($context->cookie) || !(int) $context->cookie->id_customer) {
            return null;
        }

        $customer = new Customer((int) $context->cookie->id_customer);

        return Validate::isLoadedObject($customer) ? $customer : null;
    }

    /**
     * @return Cart|null
     */
    private function getCheckoutCart()
    {
        $context = Context::getContext();
        if (isset($context->cart) && Validate::isLoadedObject($context->cart)) {
            return $context->cart;
        }
        if (!isset($context->cookie) || !(int) $context->cookie->id_cart) {
            return null;
        }

        $cart = new Cart((int) $context->cookie->id_cart);

        return Validate::isLoadedObject($cart) ? $cart : null;
    }

    /**
     * @param Cart $cart
     * @return bool
     */
    private function isCartReadyForOrder($cart)
    {
        return Validate::isLoadedObject($cart)
            && (int) $cart->id_customer
            && (int) $cart->id_address_delivery
            && (int) $cart->id_address_invoice
            && (int) $cart->nbProducts() > 0;
    }

    /**
     * @param Customer $customer
     * @return array|null Spam payload when the order must be blocked
     */
    private function evaluateOrderSpam(Customer $customer)
    {
        $data = [
            'email' => $customer->email,
            'firstname' => $customer->firstname,
            'lastname' => $customer->lastname,
            'message' => !is_null($customer->note) ? $customer->note : '',
            'ct_bot_detector_event_token' => Tools::getValue('ct_bot_detector_event_token', ''),
            'post_info' => ['comment_type' => 'order'],
        ];

        if ($this->isPaymentGatewayCallback()) {
            $ip = $this->getCustomerRecentIp((int) $customer->id);
            if ($ip !== '') {
                $data['sender_ip'] = $ip;
            }
        }

        $result = $this->checkSpam($data);
        if (!is_array($result) || !empty($result['errno']) || !isset($result['allow']) || $result['allow'] != 0) {
            return null;
        }

        return $result;
    }

    /**
     * @param int $idCustomer
     * @return string
     */
    private function getCustomerRecentIp($idCustomer)
    {
        $ipLong = Db::getInstance()->getValue(
            'SELECT c.ip_address
            FROM `' . _DB_PREFIX_ . 'guest` g
            INNER JOIN `' . _DB_PREFIX_ . 'connections` c ON c.id_guest = g.id_guest
            WHERE g.id_customer = ' . (int) $idCustomer . '
            ORDER BY c.date_add DESC'
        );
        if ($ipLong === false || $ipLong === null || $ipLong === '') {
            return '';
        }

        $ip = long2ip((int) $ipLong);

        return $ip && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $ip : '';
    }

    /**
     * @param Customer $customer
     * @param Cart $cart
     * @param string $comment
     * @param string $attemptedModule
     * @param string $attemptedPayment
     * @return void
     */
    private function blockOrder(Customer $customer, Cart $cart, $comment, $attemptedModule = '', $attemptedPayment = '')
    {
        $attempted = $attemptedPayment !== '' ? $attemptedPayment : $attemptedModule;
        $message = $this->buildCancellationMessage($comment, $attempted);

        try {
            if (Validate::isLoadedObject($cart) && $cart->OrderExists()) {
                $this->cancelExistingOrder($cart, $message);
            } else {
                $this->createCancelledOrder($customer, $cart, $message);
            }
        } catch (Throwable $exception) {
            PrestaShopLogger::addLog(
                'CleanTalk order block failed: ' . $exception->getMessage(),
                3,
                null,
                'Customer',
                (int) $customer->id,
                true
            );
            $this->ensureCancelledRecord($cart, $message);
        }

        $this->stopBlockedOrderRequest($comment);
    }

    /**
     * @param string $comment
     * @param string $attemptedPayment
     * @return string
     */
    private function buildCancellationMessage($comment, $attemptedPayment)
    {
        $comment = trim(strip_tags((string) $comment));
        if (function_exists('mb_substr')) {
            $comment = mb_substr($comment, 0, 800);
        } else {
            $comment = substr($comment, 0, 800);
        }

        $message = $this->l('Cancelled by CleanTalk Anti-Spam.');
        if ($attemptedPayment !== '') {
            $message .= ' ' . sprintf($this->l('Attempted payment: %s.'), $attemptedPayment);
        }
        if ($comment !== '') {
            $message .= ' ' . $comment;
        }
        if (!Validate::isCleanHtml($message)) {
            $message = $this->l('Cancelled by CleanTalk Anti-Spam.');
        }

        return $message;
    }

    /**
     * @param Customer $customer
     * @param Cart $cart
     * @param string $message
     * @return void
     */
    private function createCancelledOrder(Customer $customer, Cart $cart, $message)
    {
        $paymentModule = $this->getOrderCreatorModule();
        if (!$paymentModule || !Validate::isLoadedObject($cart) || $cart->OrderExists()) {
            return;
        }

        $this->prepareOrderContext($cart, $customer);
        $this->ensureFrontContainer();

        $this->creatingBlockedOrder = true;
        $paymentModule->validateOrder(
            (int) $cart->id,
            (int) Configuration::get('PS_OS_CANCELED'),
            (float) $cart->getOrderTotal(true, Cart::BOTH),
            'CleanTalk Anti-Spam',
            $message,
            [],
            (int) $cart->id_currency,
            false,
            $cart->secure_key ? $cart->secure_key : $customer->secure_key
        );
        $this->creatingBlockedOrder = false;
    }

    /**
     * actionDispatcherBefore runs before the front controller boots the service container.
     * Order creation uses that container for translations.
     *
     * @return void
     */
    private function ensureFrontContainer()
    {
        $context = Context::getContext();
        if (isset($context->container) && $context->container) {
            return;
        }
        if (!class_exists('\PrestaShop\PrestaShop\Adapter\ContainerBuilder')) {
            return;
        }

        $context->container = \PrestaShop\PrestaShop\Adapter\ContainerBuilder::getContainer('front', _PS_MODE_DEV_);
    }

    /**
     * Front controller has not prepared the shop context yet when the check runs
     * from actionDispatcherBefore.
     *
     * @param Cart $cart
     * @param Customer $customer
     * @return void
     */
    private function prepareOrderContext(Cart $cart, Customer $customer)
    {
        $context = Context::getContext();
        $context->cart = $cart;
        $context->customer = $customer;
        if ((int) $cart->id_shop) {
            $context->shop = new Shop((int) $cart->id_shop);
        }
        if (!isset($context->language) || !Validate::isLoadedObject($context->language)) {
            $context->language = new Language((int) ($cart->id_lang ?: Configuration::get('PS_LANG_DEFAULT')));
        }
        if (!isset($context->currency) || !Validate::isLoadedObject($context->currency)) {
            $context->currency = new Currency((int) ($cart->id_currency ?: Configuration::get('PS_CURRENCY_DEFAULT')));
        }
        if (!isset($context->country) || !Validate::isLoadedObject($context->country)) {
            $address = new Address((int) $cart->id_address_delivery);
            $idCountry = (int) $address->id_country ?: (int) Configuration::get('PS_COUNTRY_DEFAULT');
            $context->country = new Country($idCountry);
        }
    }

    /**
     * Core validateOrder() has to run on a PaymentModule. This instance is the anti-spam module
     * itself, so a shop that only has Amazon Pay or Redsys still gets a cancelled order.
     *
     * @return PaymentModule
     */
    private function getOrderCreatorModule()
    {
        return new CleantalkAntispamPayment();
    }

    /**
     * A captured payment must stay captured. logable states and a recorded payment count as paid.
     *
     * @param Order $order
     * @return bool
     */
    private function isOrderAlreadyPaid(Order $order)
    {
        if ((float) $order->total_paid_real > 0) {
            return true;
        }

        $state = new OrderState((int) $order->current_state);

        return Validate::isLoadedObject($state) && (int) $state->logable === 1;
    }

    /**
     * validateOrder can fail after the row is inserted, before the status history is stored.
     * Keep the cancelled status and the history row in that case.
     *
     * @param Cart $cart
     * @param string $message
     * @return void
     */
    private function ensureCancelledRecord(Cart $cart, $message)
    {
        if (!Validate::isLoadedObject($cart) || !$cart->OrderExists()) {
            return;
        }

        $idOrder = (int) Db::getInstance()->getValue(
            'SELECT `id_order` FROM `' . _DB_PREFIX_ . 'orders` WHERE `id_cart` = ' . (int) $cart->id
        );
        $order = new Order($idOrder);
        if (!Validate::isLoadedObject($order)) {
            return;
        }

        $cancelledState = (int) Configuration::get('PS_OS_CANCELED');
        if ((int) $order->current_state !== $cancelledState) {
            $history = new OrderHistory();
            $history->id_order = (int) $order->id;
            $context = Context::getContext();
            if (isset($context->employee->id) && (int) $context->employee->id) {
                $history->id_employee = (int) $context->employee->id;
            }
            $history->changeIdOrderState($cancelledState, $order);
            $history->add();
        }

        if ($order->payment !== 'CleanTalk Anti-Spam') {
            $order->payment = 'CleanTalk Anti-Spam';
            $order->update();
        }

        $this->addCancellationMessage($order, $message);
    }

    /**
     * @param Cart $cart
     * @param string $message
     * @return void
     */
    private function cancelExistingOrder(Cart $cart, $message)
    {
        $idOrder = (int) Db::getInstance()->getValue(
            'SELECT `id_order` FROM `' . _DB_PREFIX_ . 'orders` WHERE `id_cart` = ' . (int) $cart->id
        );
        $order = new Order($idOrder);
        if (!Validate::isLoadedObject($order) || $this->isOrderAlreadyPaid($order)) {
            return;
        }

        $cancelledState = (int) Configuration::get('PS_OS_CANCELED');
        if ((int) $order->current_state !== $cancelledState) {
            $history = new OrderHistory();
            $history->id_order = (int) $order->id;
            $context = Context::getContext();
            if (isset($context->employee->id) && (int) $context->employee->id) {
                $history->id_employee = (int) $context->employee->id;
            }
            $history->changeIdOrderState($cancelledState, $order);
            $history->addWithemail(true);
        }

        $this->addCancellationMessage($order, $message);
    }

    /**
     * @param Order $order
     * @param string $message
     * @return void
     */
    private function addCancellationMessage(Order $order, $message)
    {
        if ($message === '' || !Validate::isCleanHtml($message)) {
            return;
        }

        $existing = Message::getMessagesByOrderId((int) $order->id, true);
        if (is_array($existing)) {
            foreach ($existing as $row) {
                if (isset($row['message']) && $row['message'] === $message) {
                    return;
                }
            }
        }

        $msg = new Message();
        $msg->message = $message;
        $msg->id_cart = (int) $order->id_cart;
        $msg->id_customer = (int) $order->id_customer;
        $msg->id_order = (int) $order->id;
        $msg->private = true;
        $msg->add();
    }

    /**
     * @param string $comment
     * @return void
     */
    private function stopBlockedOrderRequest($comment)
    {
        if ($this->isPaymentGatewayCallback()) {
            if (!headers_sent()) {
                http_response_code(200);
                header('Content-Type: text/plain; charset=utf-8');
            }
            die('OK');
        }

        $this->doBlockPage($comment);
    }

    public function hookActionNewsletterRegistrationBefore($params)
    {
        $data = [];
        $data['email'] = isset($params['email']) ? $params['email'] : '';
        $data['ct_bot_detector_event_token'] = Tools::getValue('ct_bot_detector_event_token', '');
        $data['post_info']['comment_type'] = 'contact_form_prestashop_newsletter';
        $cleantalk_check = $this->checkSpam($data);
        if ($cleantalk_check['allow'] == 0) {
            $is_subscription_call = false;
            $backtrace = false;
            if (is_callable('debug_backtrace')) {
                $backtrace = @debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
            }
            if (is_array($backtrace)) {
                $backtrace = implode(",", array_map(function ($item) {
                    return $item['class'];
                }, $backtrace));
                $is_subscription_call = strpos($backtrace, 'EmailsubscriptionSubscriptionModuleFrontController') !== false;
            }
            if ($is_subscription_call) {
                $params['hookError'] = $cleantalk_check['comment'];
                return;
            }
            die();
        }
    }

    /**
     * @param array $data
     * @param bool $is_check_register
     * @return array
     */
    private function checkSpam($data, $is_check_register = false)
    {
        // Return default "allowed" result if API key is not configured
        if ( ! Configuration::get('CLEANTALKANTISPAM_API_KEY') ) {
            return [
                'allow' => 1,
                'comment' => '',
            ];
        }

        $sender_nickname = $data['nickname'] ?? '';
        $sender_nickname .= isset($data['firstname']) ? ' ' . $data['firstname'] : '';
        $sender_nickname .= isset($data['lastname']) ? ' ' . $data['lastname'] : '';

        $post_info = [
            'post_url' => Server::get('HTTP_REFERER'),
        ];
        if ( isset($data['post_info']['comment_type']) ) {
            $post_info['comment_type'] = $data['post_info']['comment_type'];
        }

        $sender_info = $this->getSenderInfo();
        if ( ! empty($data['sender_info']) && is_array($data['sender_info']) ) {
            $sender_info = array_merge($sender_info, $data['sender_info']);
        }

        $params = [
            'auth_key'        => Configuration::get('CLEANTALKANTISPAM_API_KEY'),
            'agent'           => $this->engine,
            'sender_ip'       => !empty($data['sender_ip']) ? $data['sender_ip'] : Helper::ipGet('real', false),
            'x_forwarded_for' => Helper::ipGet('x_forwarded_for', false),
            'x_real_ip'       => Helper::ipGet('x_real_ip', false),
            'sender_info'     => $sender_info,
            'sender_email'    => isset($data['email']) ? $data['email'] : '',
            'sender_nickname' => $sender_nickname,
            'message'         => isset($data['message']) ? $data['message'] : '',
            'post_info'       => $post_info,
            'event_token'     => isset($data['ct_bot_detector_event_token']) ? $data['ct_bot_detector_event_token'] : '',
            'event_token_enabled'=> (bool) Configuration::get('CLEANTALKANTISPAM_ENABLE_BOTDETECTOR'),
        ];

        $ct_request = new CleantalkRequest($params);

        $ct                 = new Cleantalk();
        $ct->server_url     = 'https://moderate.cleantalk.org';

        $result = $is_check_register ? $ct->isAllowUser($ct_request) : $ct->isAllowMessage($ct_request);
        $result = json_decode(json_encode($result), true);

        return $result;
    }

    private function checkRegistrationSpam()
    {
        if ( $this->registrationAlreadyProcessed ) {
            return true;
        }
        $data = Tools::getAllValues();
        $cleantalk_check = $this->checkSpam($data, true);
        if ($cleantalk_check['allow'] == 0) {
            $this->doBlockPage($cleantalk_check['comment']);
        }
        $this->registrationAlreadyProcessed = true;
        return true;
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

    private function getSenderInfo()
    {
        return [
            'REFFERRER' => Server::get('HTTP_REFERER'),
        ];
    }

    /**
     * Extract email, name and message from Form Builder Pro form data.
     * Searches through all fields for typical field names.
     *
     * @param array $form_data
     * @return array
     */
    private function extractFormBuilderData($form_data)
    {
        $data = [];

        // Common field name patterns for email
        $email_fields = ['email', 'mail', 'e-mail', 'from'];
        // Common field name patterns for message
        $message_fields = ['message', 'comment', 'comments', 'text', 'body', 'content'];

        foreach ($form_data as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            $key_lower = strtolower($key);

            if (empty($data['email'])) {
                foreach ($email_fields as $pattern) {
                    if (strpos($key_lower, $pattern) !== false && filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        $data['email'] = $value;
                        break;
                    }
                }
            }

            if (empty($data['firstname'])) {
                if (strpos($key_lower, 'first') !== false || $key_lower === 'name') {
                    $data['firstname'] = $value;
                }
            }

            if (empty($data['lastname'])) {
                if (strpos($key_lower, 'last') !== false) {
                    $data['lastname'] = $value;
                }
            }

            if (empty($data['message'])) {
                foreach ($message_fields as $pattern) {
                    if (strpos($key_lower, $pattern) !== false) {
                        $data['message'] = $value;
                        break;
                    }
                }
            }
        }

        // If no email found by field name, try to find any valid email in form data
        if (empty($data['email'])) {
            foreach ($form_data as $key => $value) {
                if (is_string($value) && filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $data['email'] = $value;
                    break;
                }
            }
        }

        // Build message from all text fields if no specific message field found
        if (empty($data['message'])) {
            $message_parts = [];
            $skip_fields = ['idform', 'id_lang', 'id_shop', 'Conditions', 'ConditionsHide',
                           'gSubmitForm', 'usingajax', 'ct_bot_detector_event_token'];
            foreach ($form_data as $key => $value) {
                if (is_string($value) && !empty($value) && !in_array($key, $skip_fields)
                    && strpos($key, 'input_') === 0) {
                    $message_parts[] = $value;
                }
            }
            if (!empty($message_parts)) {
                $data['message'] = implode(' ', $message_parts);
            }
        }

        return $data;
    }
}

/**
 * PaymentModule used only to store an order that CleanTalk has rejected.
 */
class CleantalkAntispamPayment extends PaymentModule
{
    public function __construct()
    {
        $this->name = 'cleantalkantispam';
        parent::__construct();
        $this->active = true;
    }
}
