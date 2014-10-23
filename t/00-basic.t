#!/usr/bin/env perl

use strict;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

BEGIN {
    use_ok('Mock::Apache')
	or die 'cannot load Mock::Apache';
}
use Apache::Constants qw(:common);

my $DEBUG      = 0;     # set to 1 for method tracing
my $start_time = time;

my $mock_apache = Mock::Apache->setup_server(DEBUG => $DEBUG);
my $mock_client = $mock_apache->mock_client();
my $request     = $mock_client->new_request(GET => 'http://example.com/index.html');

my $server  = $request->server;
isa_ok($server, 'Apache::Server');
is($request->server, $Apache::server, '$r->server gives same as $Apache::server object');
is($server->server_hostname, 'server.example.com',           '$s->server_hostname');
is($server->server_admin,    'webmaster@server.example.com', '$s->server_admin');

cmp_ok($request->request_time, '>=', $start_time, 'request time is sane (not earlier than start of test)');
cmp_ok($request->request_time, '<=', time,        'request time is sane (not later than now)');

ok(!exists $ENV{REMOTE_HOST}, 'no $ENV{REMOTE_HOST} entry prior to invoking handler');
$mock_apache->execute_handler(\&handler, $request);
ok(!exists $ENV{REMOTE_HOST}, 'no $ENV{REMOTE_HOST} entry after invoking handler');

done_testing();


sub handler {
    my $r = shift;

    subtest in_handler => sub {
	ok(exists $ENV{REMOTE_HOST}, 'in handler: $ENV{REMOTE_HOST} entry exists');
	ok($r->is_initial_req,       'in handler: $r->is_initial_req');
	ok($r->is_main,              'in handler: $r->is_main');
	is($r->server->server_admin, 'webmaster@server.example.com', 'in handler: $s->server_admin');
    };
    return OK;
}


