package net.portswigger.mcp.jobs;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.timeout.ReadTimeoutHandler;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** A run-scoped loopback target. Observations alone do not attest Burp's tool source. */
public final class CapabilityFixture implements AutoCloseable {
    private final EventLoopGroup events = new NioEventLoopGroup(1);
    private final Channel server;
    private final String prefix = "/" + UUID.randomUUID();
    private String pending;
    private int accepted;

    public CapabilityFixture() throws IOException {
        try {
            server = new ServerBootstrap().group(events).channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast(new ReadTimeoutHandler(15), new HttpServerCodec(),
                            new HttpObjectAggregator(1024 * 1024), new SimpleChannelInboundHandler<FullHttpRequest>() {
                                @Override protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
                                    handle(ctx, request);
                                }
                            });
                    }
                }).bind(new InetSocketAddress("127.0.0.1", 0)).syncUninterruptibly().channel();
        } catch (Throwable failure) {
            events.shutdownGracefully();
            throw failure;
        }
    }

    public URI baseUri() {
        return URI.create("http://127.0.0.1:" + ((InetSocketAddress) server.localAddress()).getPort() + prefix + "/");
    }

    public synchronized int acceptedChallenges() {
        return accepted;
    }

    /** Operator entry point for observing a bounded local run from a terminal. */
    public static void main(String[] args) throws Exception {
        try (CapabilityFixture fixture = new CapabilityFixture()) {
            System.out.println("Local fixture: " + fixture.baseUri());
            System.out.println("GET issue, then POST verify with header X-Fixture-Token.");
            System.out.println("Press Enter to stop and display accepted one-time tokens.");
            System.in.read();
            System.out.println("Accepted one-time tokens: " + fixture.acceptedChallenges());
        }
    }

    private synchronized void handle(ChannelHandlerContext ctx, FullHttpRequest request) {
        String path = new QueryStringDecoder(request.uri()).rawPath();
        HttpResponseStatus status = HttpResponseStatus.NOT_FOUND;
        String body = "";
        if (path.equals(prefix + "/issue") && HttpMethod.GET.equals(request.method())) {
            pending = UUID.randomUUID().toString();
            body = pending;
            status = HttpResponseStatus.OK;
        } else if (path.equals(prefix + "/verify") && HttpMethod.POST.equals(request.method())) {
            status = HttpResponseStatus.FORBIDDEN;
            if (pending != null && pending.equals(request.headers().get("X-Fixture-Token"))) {
                pending = null;
                accepted++;
                status = HttpResponseStatus.OK;
                body = "accepted";
            }
        }
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status,
            Unpooled.copiedBuffer(body, StandardCharsets.UTF_8));
        response.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-store");
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        HttpUtil.setContentLength(response, response.content().readableBytes());
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
    public void close() {
        server.close().syncUninterruptibly();
        events.shutdownGracefully(0, 2, java.util.concurrent.TimeUnit.SECONDS).syncUninterruptibly();
    }
}
